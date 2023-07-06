import binascii
import time
from collections import defaultdict
from functools import wraps
from logging import getLogger
from typing import DefaultDict, Optional

from django.conf import settings
from django.core.cache import cache
from django.db import IntegrityError, connection
from stellar_sdk import StrKey
from stellar_sdk.soroban import SorobanServer
from stellar_sdk.soroban.exceptions import RequestException
from stellar_sdk.soroban.soroban_rpc import EventFilter
from stellar_sdk.xdr import PublicKeyType, SCAddressType, SCVal, SCValType

from core import models as core_models
from core.event_handler import soroban_event_handler

logger = getLogger("alerts")


def unpack_scval(val: SCVal):
    match val.type:
        case SCValType.SCV_MAP:
            return {unpack_scval(entry.key): unpack_scval(entry.val) for entry in val.map.sc_map}
        case SCValType.SCV_VEC:
            return [unpack_scval(entry) for entry in val.vec.sc_vec]
        case SCValType.SCV_BOOL:
            return val.b
        case SCValType.SCV_SYMBOL:
            return val.sym.sc_symbol.decode().strip()
        case SCValType.SCV_BYTES:
            try:
                return val.bytes.sc_bytes.decode().strip()
            except UnicodeDecodeError:
                return StrKey.encode_ed25519_public_key(val.bytes.sc_bytes)
        case SCValType.SCV_ADDRESS:
            match val.address.type:
                case SCAddressType.SC_ADDRESS_TYPE_ACCOUNT:
                    match val.address.account_id.account_id.type:
                        case PublicKeyType.PUBLIC_KEY_TYPE_ED25519:
                            return StrKey.encode_ed25519_public_key(val.address.account_id.account_id.ed25519.uint256)
                case SCAddressType.SC_ADDRESS_TYPE_CONTRACT:
                    return StrKey.encode_contract(val.address.contract_id.hash)
        case SCValType.SCV_U32:
            return val.u32.uint32
        case SCValType.SCV_I32:
            return val.i32.int32
        case SCValType.SCV_U64:
            return val.u64.uint64
        case SCValType.SCV_I64:
            return val.i64.int64
        case SCValType.SCV_U128:
            return val.u128.hi.uint64 << 64 | val.u128.lo.uint64
        case SCValType.SCV_I128:
            return val.i128.hi.int64 << 64 | val.i128.lo.uint64
        case _:
            return str(val)


def retry(description: str):
    """
    Args:
        description: short description of wrapped action, used for logging

    Returns:
        wrapped function

    wraps function in retry functionality
    """

    def wrap(f):
        @wraps(f)
        def action(*args, **kwargs):
            retry_delays = settings.RETRY_DELAYS
            max_delay = retry_delays[-1]
            retry_delays = iter(retry_delays)

            def log_and_sleep(err_msg: str, log_exception=False):
                retry_delay = next(retry_delays, max_delay)
                err_msg = f"{err_msg} while {description}. "
                if block_number := kwargs.get("block_number"):
                    err_msg += f"Block number: {block_number}. "
                if block_hash := kwargs.get("block_hash"):
                    err_msg += f"Block hash: {block_hash}. "
                err_msg += f"Retrying in {retry_delay}s ..."
                if log_exception:
                    logger.exception(err_msg)
                else:
                    logger.error(err_msg)
                time.sleep(retry_delay)

            while True:
                try:
                    return f(*args, **kwargs)
                except RequestException as exc:
                    match exc.message:
                        case "start is after newest ledger":
                            log_and_sleep("RequestException (ahead of chain)")
                        case "start is before oldest ledger":
                            raise NoLongerAvailableException
                        case _:
                            log_and_sleep(f"RequestException | {exc.message}", log_exception=True)
                except Exception:  # noqa E722
                    log_and_sleep("Unexpected error", log_exception=True)

        return action

    return wrap


class SorobanException(Exception):
    msg = None

    def __init__(self, *args):
        args = (self.msg,) if not args else args
        super().__init__(*args)


class OutOfSyncException(SorobanException):
    msg = "DB and chain are unrecoverably out of sync!"


class NoLongerAvailableException(SorobanException):
    msg = "The requested ledger is no longer available."


class SorobanService(object):
    soroban = None

    @retry("initializing blockchain connection")
    def __init__(self):
        self.soroban = SorobanServer(
            server_url=settings.BLOCKCHAIN_URL,
        )

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.soroban.close()

    @staticmethod
    def sleep(start_time):
        """
        Args:
            start_time: start time

        Returns:
            None

        ensure at least BLOCK_CREATION_INTERVAL sleep time
        """
        elapsed_time = time.time() - start_time
        if elapsed_time < settings.BLOCK_CREATION_INTERVAL:
            time.sleep(settings.BLOCK_CREATION_INTERVAL - elapsed_time)

    def clear_db_and_cache(self, start_time: float = None):
        """
        Args:
            start_time: time since last block was fetched from chain

        empties db, fetches seed accounts, sleeps if start_time was given, returns start Block
        """
        logger.info("DB and chain are out of sync! Recreating DB...")
        cache.clear()
        with connection.cursor() as cursor:
            cursor.execute(
                """
                truncate core_block;
                truncate core_account cascade;
                """
            )
        if start_time:
            self.sleep(start_time=start_time)

    def find_start_ledger(self, lower_bound: int = 0):
        """
        searches for the oldest ledger idx starting from envvar SOROBAN_START_LEDGER

        Args:
            lower_bound: lower bound for the idx search

        Returns:
            oldest ledger idx
        """

        def check(start_ledger):
            try:
                self.soroban.get_events(start_ledger=start_ledger)
            except RequestException as exc:
                match exc.message:
                    case "start is before oldest ledger":
                        return "<"
                    case "start is after newest ledger":
                        return ">"
                    case _:
                        raise

        idx = settings.SOROBAN_START_LEDGER
        while check(idx) == "<":  # find upper bound
            idx *= 2
        higher_bound = idx + 1  # upper bound has to be exclusive

        while True:  # binary search to find smallest start_ledger
            idx = (lower_bound + higher_bound) // 2
            match check(idx):
                case ">":
                    higher_bound = idx
                case "<":
                    lower_bound = idx
                case _:  # check if previous start_ledger exists
                    logger.info(f"Searching for start_ledger... {idx}")
                    if check(idx - 1) == "<":
                        return idx
                    higher_bound = idx

    @staticmethod
    def set_trusted_contract_ids() -> [str]:
        """
        sets "trusted_contract_ids" to CORE_CONTRACT_ADDRESS, VOTES_CONTRACT_ADDRESS (provided via env)
        + all Asset IDs

        Returns:
            list of trusted contract IDs
        """
        trusted_contract_ids = [
            binascii.hexlify(StrKey.decode_contract(settings.CORE_CONTRACT_ADDRESS)),
            binascii.hexlify(StrKey.decode_contract(settings.VOTES_CONTRACT_ADDRESS)),
            *core_models.Asset.objects.values_list("id", flat=True),
        ]
        cache.set(key="trusted_contract_ids", value=trusted_contract_ids)
        return trusted_contract_ids

    def get_events_filters(self):
        """
        creates list of EventFilters for soroban.get_events

        Returns:
            List of EventFilters
        """
        return [
            EventFilter(
                contractIds=list(filter(None, cache.get(key="trusted_contract_ids") or self.set_trusted_contract_ids()))
            )
        ]

    def fetch_and_parse_block(self, start_ledger: int) -> Optional[int]:
        """
        Args:
            start_ledger: (inclusive) block number to start fetching event_data for

        Returns:
            biggest existing block number on chain

        fetches event_data from chain starting from "start_ledger" (inclusive),
        sorts event_data by block number and creates one block for each, storing all it's event data.
        """
        res = retry("fetching event data")(self.soroban.get_events)(
            start_ledger=start_ledger, filters=self.get_events_filters(), limit=10000
        )
        # parse event data
        contract_ids = set()
        events_per_block: DefaultDict[int, list] = defaultdict(list)
        for event in res.events:
            contract_ids.add(event.contract_id)
            events_per_block[event.ledger].append(
                (
                    event.contract_id,
                    event.id,
                    [unpack_scval(SCVal.from_xdr(topic)) for topic in event.topic],
                    unpack_scval(SCVal.from_xdr(event.value.xdr)),
                )
            )
        core_models.Contract.objects.bulk_create(
            [core_models.Contract(id=contract_id) for contract_id in contract_ids], ignore_conflicts=True
        )
        for block in core_models.Block.objects.bulk_create(
            core_models.Block(number=ledger, event_data=event_data) for ledger, event_data in events_per_block.items()
        ):
            soroban_event_handler.execute_actions(block=block)
        return max(events_per_block.keys()) if events_per_block else res.latest_ledger

    def listen(self):
        for block in core_models.Block.objects.filter(executed=False).order_by("number"):
            soroban_event_handler.execute_actions(block=block)
        latest_block = core_models.Block.objects.order_by("-number").first()
        latest_block_number = latest_block and latest_block.number + 1 or self.find_start_ledger()
        while True:
            start_time = time.time()
            logger.info(f"Listening... Latest block number: {latest_block_number}")
            try:
                latest_block_number = self.fetch_and_parse_block(start_ledger=latest_block_number)
            except IntegrityError:
                self.clear_db_and_cache(start_time=start_time)
                latest_block_number = self.find_start_ledger()
            except NoLongerAvailableException:
                latest_block_number = self.find_start_ledger(lower_bound=latest_block and latest_block.number or 0)
            else:
                latest_block_number += 1

            self.sleep(start_time=start_time)


soroban_service = SorobanService()
