import base64
import binascii
import time
from collections import defaultdict
from functools import wraps
from json import JSONDecodeError
from logging import getLogger
from typing import DefaultDict, Optional, Type

from django.conf import settings
from django.core.cache import cache
from django.db import IntegrityError, connection
from stellar_sdk import Keypair, StrKey
from stellar_sdk.soroban import SorobanServer
from stellar_sdk.soroban.exceptions import RequestException
from stellar_sdk.soroban.jsonrpc import Request, Response
from stellar_sdk.soroban.server import V  # noqa
from stellar_sdk.soroban.soroban_rpc import EventFilter
from stellar_sdk.xdr import SCAddressType, SCVal, SCValType

from core import models as core_models
from core.event_handler import soroban_event_handler

logger = getLogger("alerts")
slack_logger = getLogger("alerts.slack")


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
            if val.address.type == SCAddressType.SC_ADDRESS_TYPE_ACCOUNT:
                return StrKey.encode_ed25519_public_key(val.address.account_id.account_id.ed25519.uint256)
            else:  # SCAddressType.SC_ADDRESS_TYPE_CONTRACT:
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
            slack_logger.error(f"Unhandled SCValType: {str(val)}")
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

            def log_and_sleep(err_msg: str, log_exception=False, stop_at_max_retry=False, log_to_slack=True):
                _logger = slack_logger if log_to_slack else logger
                retry_delay = next(retry_delays, max_delay)
                if stop_at_max_retry and retry_delay == max_delay:
                    logger.error("Breaking retry.")
                    raise OutOfSyncException
                err_msg = f"{err_msg} while {description}. Retrying in {retry_delay}s ..."
                if log_exception:
                    _logger.exception(err_msg)
                else:
                    _logger.error(err_msg)
                time.sleep(retry_delay)

            while True:
                try:
                    return f(*args, **kwargs)
                except RequestException as exc:
                    match exc.message:
                        case "start is after newest ledger":
                            log_and_sleep(
                                "RequestException (ahead of chain)", stop_at_max_retry=True, log_to_slack=False
                            )
                        case "start is before oldest ledger":
                            raise NoLongerAvailableException
                        case "404 Not Found":
                            log_and_sleep("RequestException (404)")
                        case _:
                            match exc.code:
                                case 502:
                                    log_and_sleep("RequestException (502 Bad Gateway)", log_to_slack=False)
                                case 503:
                                    log_and_sleep(
                                        "RequestException (503 Service Temporarily Unavailable)", log_to_slack=False
                                    )
                                case _:
                                    log_and_sleep(f"RequestException ({exc.message})", log_exception=True)
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


class RobustSorobanServer(SorobanServer):
    """
    added JSONDecodeError handling
    """

    def _post(self, request_body: Request, response_body_type: Type[V]) -> V:
        json_data = request_body.dict(by_alias=True)
        data = self._client.post(
            self.server_url,
            json_data=json_data,
        )
        try:
            response = Response[response_body_type, str].parse_obj(data.json())
        except JSONDecodeError:
            raise RequestException(code=data.status_code, message=data.text)
        if response.error:
            raise RequestException(code=response.error.code, message=response.error.message)
        return response.result


class SorobanService(object):
    soroban: RobustSorobanServer = None

    @retry("initializing blockchain connection")
    def __init__(self):
        self.soroban = RobustSorobanServer(server_url=self.set_config()["blockchain_url"])

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.soroban.close()

    @staticmethod
    def verify(address: str, challenge_address: str, signature: str) -> bool:
        """
        Args:
            address: Account.address / public key to verify signature for
            challenge_address: Account.address / public key the challenge has been created for
            signature: b64 encoded, signed challenge key

        Returns:
            bool

        verifies whether the given signature matches challenge key signed by address
        """

        if not (challenge_token := cache.get(challenge_address)):
            return False
        try:
            Keypair.from_public_key(address).verify(
                data=challenge_token.encode(), signature=base64.b64decode(signature.encode())
            )
            return True
        except Exception:  # noqa E722
            return False

    @staticmethod
    def sleep(start_time):
        """
        Args:
            start_time: start time

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
        slack_logger.info("DB and chain are out of sync! Recreating DB...")
        cache.clear()
        with connection.cursor() as cursor:
            cursor.execute(
                """
                truncate core_block;
                truncate core_account cascade;
                truncate core_contract cascade;
                """
            )
        cache.set(key="restart_listener", value=True)
        if start_time:
            self.sleep(start_time=start_time)

    @staticmethod
    def set_config(data: dict = None) -> dict:
        """
        Args:
            data: config data to set

        Returns:
            current config data

        sets soroban config data cache
        """
        data = {
            "core_contract_address": settings.CORE_CONTRACT_ADDRESS,
            "votes_contract_address": settings.VOTES_CONTRACT_ADDRESS,
            "assets_wasm_hash": settings.ASSETS_WASM_HASH,
            "blockchain_url": settings.BLOCKCHAIN_URL,
            "network_passphrase": settings.NETWORK_PASSPHRASE,
            **(cache.get("soroban_config") or {}),
            **(data or {}),
        }
        cache.set(key="soroban_config", value=data)
        return data

    def set_trusted_contract_ids(self) -> [str]:
        """
        sets "trusted_contract_ids" to
            cache["config"]["core_contract_address"],
            cache["config"]["votes_contract_address"],
            all Asset IDs

        Returns:
            list of trusted contract IDs
        """
        config = self.set_config()
        trusted_contract_ids = [
            binascii.hexlify(StrKey.decode_contract(config["core_contract_address"])),
            binascii.hexlify(StrKey.decode_contract(config["votes_contract_address"])),
            *core_models.Asset.objects.values_list("id", flat=True),
        ]
        cache.set(key="trusted_contract_ids", value=trusted_contract_ids)
        return trusted_contract_ids

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

    def get_events_filters(self):
        """
        creates list of EventFilters for soroban.get_events
        each contains up to 5 contract IDs

        Returns:
            List of EventFilters
        """
        trusted_contract_ids = list(
            filter(None, cache.get(key="trusted_contract_ids") or self.set_trusted_contract_ids())
        )
        return [
            EventFilter(contractIds=trusted_contract_ids[i : i + 5]) for i in range(0, len(trusted_contract_ids), 5)
        ]

    def fetch_event_data(self, start_ledger: int) -> Optional[int]:
        """
        Args:
            start_ledger: (inclusive) block number to start fetching event_data for

        Returns:
            biggest existing block number on chain

        fetches event_data from chain starting from "start_ledger" (inclusive),
        sorts event_data by block number and creates one block for each, storing all it's event data.
        """
        contract_ids = set()
        events_per_block: DefaultDict[int, list] = defaultdict(list)
        latest_ledger = 0
        for i in range(0, len(filters := self.get_events_filters()), 5):
            # 1 request with up to 5 filters each containing up to 5 contract IDs
            res = retry("fetching event data")(self.soroban.get_events)(
                start_ledger=start_ledger, filters=filters[i : i + 5], limit=10000
            )
            latest_ledger = max(latest_ledger, res.latest_ledger)
            # parse event data
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
        return max(events_per_block.keys()) if events_per_block else latest_ledger

    def listen(self):
        while True:
            # reinitializing connection to the chain
            if cache.get("restart_listener"):
                logger.info("Restarting listener...")
                self.soroban.close()
                self.soroban = retry("reinitializing blockchain connection")(RobustSorobanServer)(
                    server_url=self.set_config()["blockchain_url"]
                )
                cache.delete("restart_listener")
            # execute existing Blocks
            for block in core_models.Block.objects.filter(executed=False).order_by("number"):
                soroban_event_handler.execute_actions(block=block)
            latest_block = core_models.Block.objects.order_by("-number").first()
            latest_block_number = latest_block and latest_block.number + 1 or self.find_start_ledger()
            while not cache.get("restart_listener"):
                start_time = time.time()
                logger.info(f"Listening... Latest block number: {latest_block_number}")
                try:
                    latest_block_number = self.fetch_event_data(start_ledger=latest_block_number)
                except (IntegrityError, OutOfSyncException):
                    self.clear_db_and_cache(start_time=start_time)
                    latest_block_number = self.find_start_ledger()
                except NoLongerAvailableException:
                    latest_block_number = self.find_start_ledger(lower_bound=latest_block and latest_block.number or 0)
                else:
                    latest_block_number += 1

                self.sleep(start_time=start_time)


soroban_service = SorobanService()
