import time
from collections import defaultdict
from functools import wraps
from logging import getLogger
from typing import DefaultDict, Tuple

from django.conf import settings
from django.db import connection
from stellar_sdk import StrKey
from stellar_sdk.soroban import SorobanServer
from stellar_sdk.soroban.exceptions import RequestException
from stellar_sdk.xdr import PublicKeyType, SCAddressType, SCVal, SCValType

from core import models as core_models
from core.event_handler import soroban_event_handler

logger = getLogger("alerts")


# todo replace this
def unpack_scval(val: SCVal):
    match val.type:
        case SCValType.SCV_MAP:
            return {unpack_scval(entry.key): unpack_scval(entry.val) for entry in val.map.sc_map}
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
                    return StrKey.encode_ed25519_public_key(val.address.contract_id.hash)
        case SCValType.SCV_VEC:
            return [unpack_scval(entry) for entry in val.vec.sc_vec]
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
                # except WebSocketConnectionClosedException:
                #     log_and_sleep("WebSocketConnectionClosedException")
                except ConnectionRefusedError:
                    log_and_sleep("ConnectionRefusedError")
                except BrokenPipeError:
                    log_and_sleep("BrokenPipeError")
                except Exception:  # noqa E722
                    log_and_sleep("Unexpected error", log_exception=True)

        return action

    return wrap


class SorobanException(Exception):
    pass


class OutOfSyncException(SorobanException):
    msg = "DB and chain are unrecoverably out of sync!"

    def __init__(self, *args):
        args = (self.msg,) if not args else args
        super().__init__(*args)


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

    def clear_db(self, start_time: float = None):
        """
        Args:
            start_time: time since last block was fetched from chain

        Returns:
            empty db start Block

        empties db, fetches seed accounts, sleeps if start_time was given, returns start Block
        """
        logger.info("DB and chain are out of sync! Recreating DB...")
        with connection.cursor() as cursor:
            cursor.execute(
                """
                truncate core_block;
                truncate core_account cascade;
                """
            )
        if start_time:
            self.sleep(start_time=start_time)

    def find_start_ledger(self):
        """
        searches for the oldest ledger idx starting from envvar SOROBAN_START_LEDGER

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
        lower_bound = 0
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

    def fetch_and_parse_block(self, start_ledger: int) -> Tuple[int, int]:
        """
        Args:
            start_ledger: (inclusive) block number to start fetching event_data for

        Returns:
            (highest created block number, biggest existing block number on chain)

        fetches event_data from chain starting from "start_ledger" (inclusive),
        sorts event_data by block number and creates one block for each, storing all it's event data.
        """
        try:
            res = self.soroban.get_events(start_ledger=start_ledger, limit=10000)
        except RequestException as ex:
            match ex.message:
                case "start is after newest ledger":
                    self.clear_db()
                    return 0, 0
                # todo handle other errors
                case _:
                    raise
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
        blocks = core_models.Block.objects.bulk_create(
            core_models.Block(number=ledger, event_data=event_data) for ledger, event_data in events_per_block.items()
        )
        for block in blocks:
            soroban_event_handler.execute_actions(block=block)
        return max(events_per_block.keys()) if events_per_block else start_ledger - 1, res.latest_ledger

    def listen(self):
        for block in core_models.Block.objects.filter(executed=False).order_by("number"):
            soroban_event_handler.execute_actions(block=block)
        latest_block = core_models.Block.objects.order_by("-number").first()
        latest_block_number = (latest_block and latest_block.number) or self.find_start_ledger()

        while True:
            start_time = time.time()
            latest_block_number, largest_block_number = self.fetch_and_parse_block(start_ledger=latest_block_number + 1)
            logger.info(
                f"Listening... Latest block number containing event_data: {latest_block_number} "
                f"| Largest existing block number: {largest_block_number}"
            )
            self.sleep(start_time=start_time)


soroban_service = SorobanService()
