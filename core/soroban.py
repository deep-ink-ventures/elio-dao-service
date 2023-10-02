import base64
import binascii
import time
from collections import defaultdict
from copy import deepcopy
from functools import wraps
from json import JSONDecodeError
from logging import getLogger
from typing import Callable, Collection, DefaultDict, List, Optional, Type, Union

from django.conf import settings
from django.core.cache import cache
from django.db import IntegrityError, connection
from stellar_sdk import (
    Address,
    InvokeHostFunction,
    Keypair,
    Network,
    SorobanServer,
    StrKey,
    TransactionBuilder,
    scval,
)
from stellar_sdk import xdr as stellar_xdr
from stellar_sdk.exceptions import SorobanRpcErrorResponse
from stellar_sdk.soroban_rpc import (
    EventFilter,
    GetTransactionStatus,
    Request,
    Response,
    SendTransactionStatus,
)
from stellar_sdk.soroban_server import V
from stellar_sdk.utils import sha256
from stellar_sdk.xdr import (
    HostFunction,
    HostFunctionType,
    InvokeHostFunctionOp,
    OperationBody,
    OperationResultTr,
    OperationType,
    SCAddress,
    SCAddressType,
    SCSymbol,
    SCVal,
    SCValType,
    SCVec,
    SorobanAuthorizationEntry,
)

from core import models as core_models
from core.event_handler import soroban_event_handler

logger = getLogger("alerts")
slack_logger = getLogger("alerts.slack")


def unpack_sc(val):
    if isinstance(val, SCVec):
        return [unpack_sc(_val) for _val in val.sc_vec]
    elif isinstance(val, SCAddress):
        if val.type == SCAddressType.SC_ADDRESS_TYPE_ACCOUNT:
            return StrKey.encode_ed25519_public_key(val.account_id.account_id.ed25519.uint256)
        else:  # SCAddressType.SC_ADDRESS_TYPE_CONTRACT:
            return StrKey.encode_contract(val.contract_id.hash)
    elif isinstance(val, SCSymbol):
        return val.sc_symbol.decode().strip()

    match val.type:
        case SCValType.SCV_MAP:
            return {unpack_sc(entry.key): unpack_sc(entry.val) for entry in val.map.sc_map}
        case SCValType.SCV_VEC:
            return [unpack_sc(entry) for entry in val.vec.sc_vec]
        case SCValType.SCV_VOID:
            return
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
        case SCValType.SCV_ERROR:
            err = val.error
            return f"type: {err.type.name}: {err.type.value} | code: {err.code.name}: {err.code.value}"
        case SCValType.SCV_STRING:
            return val.str.sc_string.decode()

    slack_logger.error(f"Unhandled SC(Val)Type: {str(val)}")
    return str(val)


def unpack_operation_body(body: OperationBody):
    match body.type:
        case OperationType.INVOKE_HOST_FUNCTION:
            return body.invoke_host_function_op
        case _:
            slack_logger.error(f"Unhandled OperationBody: {str(body)}")
            return str(body)


def unpack_host_function(func: HostFunction):
    match func.type:
        case HostFunctionType.HOST_FUNCTION_TYPE_INVOKE_CONTRACT:
            return {
                "contract_address": unpack_sc(func.invoke_contract.contract_address),
                "func_name": unpack_sc(func.invoke_contract.function_name),
                "func_args": [unpack_sc(arg) for arg in func.invoke_contract.args],
            }
        case _:
            slack_logger.error(f"Unhandled HostFunction: {str(func)}")
            return str(func)


def unpack_operation_result_tr(val: OperationResultTr):
    match val.type:
        case OperationType.INVOKE_HOST_FUNCTION:
            return val.invoke_host_function_result.code


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

                # respect restart_listener flag
                # avoids getting stuck in retry with outdated args
                if cache.get("restart_listener"):
                    raise RestartListenerException

                time.sleep(retry_delay)

            while True:
                try:
                    return f(*args, **kwargs)
                except SorobanRpcErrorResponse as exc:
                    match exc.message:
                        case "start is after newest ledger":
                            log_and_sleep(
                                "SorobanRpcErrorResponse (ahead of chain)", stop_at_max_retry=True, log_to_slack=False
                            )
                        case "start is before oldest ledger":
                            raise NoLongerAvailableException
                        case "404 Not Found":
                            log_and_sleep("SorobanRpcErrorResponse (404)")
                        case _:
                            match exc.code:
                                case 502:
                                    log_and_sleep("SorobanRpcErrorResponse (502 Bad Gateway)", log_to_slack=False)
                                case 503:
                                    log_and_sleep(
                                        "SorobanRpcErrorResponse (503 Service Temporarily Unavailable)",
                                        log_to_slack=False,
                                    )
                                case -32602:  # invalid filter
                                    msg = (
                                        f"SorobanRpcErrorResponse ({exc.message}) "
                                        f"(trusted_contract_ids: {cache.get('trusted_contract_ids')})"
                                    )
                                    log_and_sleep(msg)
                                case _:
                                    log_and_sleep(f"SorobanRpcErrorResponse ({exc.message})", log_exception=True)
                except Exception:  # noqa E722
                    log_and_sleep("Unexpected error", log_exception=True)

        return action

    return wrap


class RestartListenerException(Exception):
    pass


class SorobanException(Exception):
    msg = None
    ctx = None

    def __init__(self, *_, ctx=None):
        self.ctx = ctx
        super().__init__(self.msg)


class OutOfSyncException(SorobanException):
    msg = "DB and chain are unrecoverably out of sync!"


class NoLongerAvailableException(SorobanException):
    msg = "The requested ledger is no longer available."


class InvalidXDRException(SorobanException):
    msg = "The XDR is invalid."


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
            response = Response[response_body_type].parse_obj(data.json())
        except JSONDecodeError:
            raise SorobanRpcErrorResponse(code=data.status_code, message=data.text)
        if response.error:
            raise SorobanRpcErrorResponse(code=response.error.code, message=response.error.message)
        return response.result


class SorobanService(object):
    soroban: RobustSorobanServer = None
    network_passphrase: str = None
    wait_for_txn_interval: int = 1  # seconds

    @retry("initializing blockchain connection")
    def __init__(self):
        config = self.set_config()
        self.soroban = RobustSorobanServer(server_url=config["blockchain_url"])
        self.network_passphrase = config["network_passphrase"]
        self.multiclique_addr = config["multiclique_contract_address"]

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.soroban.close()

    # todo replace w/ sdk version, once fixed
    @staticmethod
    def authorize_entry(
        entry: Union[stellar_xdr.SorobanAuthorizationEntry, str],
        signers: List[(Union[Keypair, Callable[[stellar_xdr.HashIDPreimage], bytes]])],
        valid_until_ledger_sequence: int,
        network_passphrase: str,
    ) -> stellar_xdr.SorobanAuthorizationEntry:
        """Actually authorizes an existing authorization entry using the given the
        credentials and expiration details, returning a signed copy.

        This "fills out" the authorization entry with a signature, indicating to the
        :class:`stellar_sdk.InvokeHostFunction` it's attached to that:

        * a particular identity (i.e. signing :class:`stellar_sdk.Keypair` or other signer)
        * approving the execution of an invocation tree (i.e. a
            simulation-acquired :class:`stellar_xdr.SorobanAuthorizedInvocation` or otherwise built)
        * on a particular network (uniquely identified by its passphrase, see :class:`stellar_sdk.Network`)
        * until a particular ledger sequence is reached.

        :param entry: an unsigned Soroban authorization entry.
        :param signers: list of either a :class:`Keypair` or a function which takes a payload
            (a :class:`stellar_xdr.HashIDPreimage` instance) input and returns a bytes signature,
            the signing key should correspond to the address in the `entry`.
        :param valid_until_ledger_sequence: the (exclusive) future ledger sequence number until which
            this authorization entry should be valid (if `currentLedgerSeq==validUntil`, this is expired)
        :param network_passphrase: the network passphrase is incorporated into the signature
            (see :class:`stellar_sdk.Network` for options)
        :return: a signed Soroban authorization entry.
        """

        if isinstance(entry, str):
            entry = stellar_xdr.SorobanAuthorizationEntry.from_xdr(entry)
        else:
            entry = deepcopy(entry)

        if entry.credentials.type != stellar_xdr.SorobanCredentialsType.SOROBAN_CREDENTIALS_ADDRESS:
            return entry

        assert entry.credentials.address is not None
        addr_auth = entry.credentials.address
        addr_auth.signature_expiration_ledger = stellar_xdr.Uint32(valid_until_ledger_sequence)

        network_id = Network(network_passphrase).network_id()
        preimage = stellar_xdr.HashIDPreimage(
            type=stellar_xdr.EnvelopeType.ENVELOPE_TYPE_SOROBAN_AUTHORIZATION,
            soroban_authorization=stellar_xdr.HashIDPreimageSorobanAuthorization(
                network_id=stellar_xdr.Hash(network_id),
                nonce=addr_auth.nonce,
                signature_expiration_ledger=addr_auth.signature_expiration_ledger,
                invocation=entry.root_invocation,
            ),
        )
        payload = sha256(preimage.to_xdr_bytes())
        signatures = []

        for signer in signers:
            if isinstance(signer, Keypair):
                signature = signer.sign(payload)
            else:
                signature = signer(preimage)
            public_key = Address.from_raw_account(signer.raw_public_key()).key
            signatures.append(
                scval.to_map(
                    {
                        scval.to_symbol("public_key"): scval.to_bytes(public_key),
                        scval.to_symbol("signature"): scval.to_bytes(signature),
                    }
                )
            )

        addr_auth.signature = scval.to_vec(signatures)
        return entry

    def create_preimage_hash(self, entry: SorobanAuthorizationEntry) -> str:
        """
        Args:
            entry: auth entry to generate preimage hash from

        Returns:
            preimage hash as b64 encoded str
        """
        addr_auth = entry.credentials.address
        # todo not sure if we need a different expiration ledger
        # addr_auth.signature_expiration_ledger = stellar_xdr.Uint32(?)

        network_id = Network(self.network_passphrase).network_id()
        preimage = stellar_xdr.HashIDPreimage(
            type=stellar_xdr.EnvelopeType.ENVELOPE_TYPE_SOROBAN_AUTHORIZATION,
            soroban_authorization=stellar_xdr.HashIDPreimageSorobanAuthorization(
                network_id=stellar_xdr.Hash(network_id),
                nonce=addr_auth.nonce,
                signature_expiration_ledger=addr_auth.signature_expiration_ledger,
                invocation=entry.root_invocation,
            ),
        )
        return base64.b64encode(sha256(preimage.to_xdr_bytes())).decode()

    def analyze_xdr(self, xdr: str):
        # todo improve: signatures? handle exceptions. move to unpack_operation_body?
        try:
            envelope = stellar_xdr.TransactionEnvelope.from_xdr(xdr=xdr)
        except binascii.Error as err:
            raise InvalidXDRException(ctx={"xdr": xdr, "error": str(err)})

        source_acc = StrKey.encode_ed25519_public_key(envelope.v1.tx.source_account.ed25519.uint256)
        if isinstance(op := unpack_operation_body(envelope.v1.tx.operations[0].body), InvokeHostFunctionOp):
            signers = []
            for entry in op.auth:
                sigs: dict | list[dict] = unpack_sc(entry.credentials.address.signature)
                if isinstance(sigs, Collection):
                    signers.extend([sig["public_key"] for sig in sigs])
                # todo check if that can happen
                else:
                    signers.append(sigs["public_key"])
            func_call = unpack_host_function(op.host_function)
            return {
                "source_acc": source_acc,
                "contract_address": func_call["contract_address"],
                "func_name": func_call["func_name"],
                "func_args": func_call["func_args"],
                "signers": signers,
                "preimage_hash": self.create_preimage_hash(entry=op.auth[0]),
            }

    def invoke_contract_func(
        self,
        func_name: str,
        func_args: list,
        signers: [Keypair],
        contract_addr: str = None,
        base_fee=100,
        timeout=300,
    ):
        if contract_addr is None:
            contract_addr = self.multiclique_addr

        metadata = {
            "contract_addr": contract_addr,
            "func_name": func_name,
            "func_args": [unpack_sc(arg) for arg in func_args],
        }
        envelope = (
            TransactionBuilder(
                source_account=self.soroban.load_account(signers[0].public_key),
                network_passphrase=self.network_passphrase,
                base_fee=base_fee,
            )
            .set_timeout(timeout)
            .append_invoke_contract_function_op(
                contract_id=contract_addr,
                function_name=func_name,
                parameters=func_args,
            )
            .build()
        )
        sim_txn = self.soroban.simulate_transaction(envelope)
        # todo fix this
        assert isinstance(envelope.transaction.operations[0], InvokeHostFunction)
        assert sim_txn.results is not None

        if _auth := sim_txn.results[0].auth:
            envelope.transaction.operations[0].auth = [
                self.authorize_entry(
                    entry=_auth[0],
                    signers=signers,
                    valid_until_ledger_sequence=sim_txn.latest_ledger + 20,
                    network_passphrase=self.network_passphrase,
                )
            ]
        envelope = self.soroban.prepare_transaction(
            transaction_envelope=envelope, simulate_transaction_response=sim_txn
        )
        envelope.transaction.fee *= 2
        envelope.transaction.soroban_data.resources.instructions.uint32 *= 2
        envelope.sign(signers[0])

        send_txn_res = self.soroban.send_transaction(envelope)
        if send_txn_res.status != SendTransactionStatus.PENDING:
            err = stellar_xdr.TransactionResult.from_xdr(send_txn_res.error_result_xdr).result.code.name
            raise SorobanException(f"send_transaction failed: {err}", ctx=metadata)

        while (get_txn_res := self.soroban.get_transaction(send_txn_res.hash)).status == GetTransactionStatus.NOT_FOUND:
            time.sleep(self.wait_for_txn_interval)

        if get_txn_res.status == GetTransactionStatus.FAILED:
            result_xdr = stellar_xdr.TransactionResult.from_xdr(get_txn_res.result_xdr)
            meta_xdr = stellar_xdr.TransactionMeta.from_xdr(get_txn_res.result_meta_xdr)
            errs = [unpack_operation_result_tr(result.tr).name for result in result_xdr.result.results]
            diagnostic_events = []
            for event in meta_xdr.v3.soroban_meta.diagnostic_events:
                _event = event.event
                body = getattr(_event.body, f"v{_event.body.v}")
                diagnostic_events.append(
                    {
                        "contract_id": _event.contract_id and StrKey.encode_contract(_event.contract_id.hash),
                        "type": _event.type.name,
                        "in_successful_contract_call": event.in_successful_contract_call,
                        "topics": unpack_sc(body.topics),
                        "data": unpack_sc(body.data),
                    }
                )
            raise SorobanException(
                f"transaction failed: {errs}", ctx={"diagnostic_events": diagnostic_events, **metadata}
            )

        return unpack_sc(stellar_xdr.TransactionMeta.from_xdr(get_txn_res.result_meta_xdr).v3.soroban_meta.return_value)

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

    def clear_db_and_cache(self, start_time: float = None, new_config: dict = None):
        """
        Args:
            start_time: time since last block was fetched from chain
            new_config: new config to set

        empties db & clears cache.
        sets flag to restart the listener.
        sets new_config if given.
        sleeps if start_time was given.
        """
        slack_logger.info("Service and chain are out of sync! Recreating DB, clearing cache, restarting listener...")
        cache.clear()
        if new_config:
            self.set_config(data=new_config)
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
            "multiclique_contract_address": settings.MULTICLIQUE_CONTRACT_ADDRESS,
            "policy_contract_address": settings.POLICY_CONTRACT_ADDRESS,
            "assets_wasm_hash": settings.ASSETS_WASM_HASH,
            "multiclique_wasm_hash": settings.MULTICLIQUE_WASM_HASH,
            "policy_wasm_hash": settings.POLICY_WASM_HASH,
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
            cache["config"]["multiclique_contract_address"],
            cache["config"]["policy_contract_address"],
            all Asset IDs

        Returns:
            list of trusted contract IDs
        """
        config = self.set_config()

        trusted_contract_ids = [
            *[
                binascii.hexlify(StrKey.decode_contract(config[addr]))
                for addr in (
                    "core_contract_address",
                    "votes_contract_address",
                    "multiclique_contract_address",
                    "policy_contract_address",
                )
                if config[addr]
            ],
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
            except SorobanRpcErrorResponse as exc:
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
                        [unpack_sc(SCVal.from_xdr(topic)) for topic in event.topic],
                        unpack_sc(SCVal.from_xdr(event.value.xdr)),
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
                self.soroban = retry("reinitializing blockchain connection")(SorobanServer)(
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
                except IntegrityError:
                    slack_logger.exception("IntegrityError")
                    self.clear_db_and_cache(start_time=start_time, new_config=self.set_config())
                    latest_block_number = self.find_start_ledger()
                except OutOfSyncException:
                    slack_logger.exception("OutOfSyncException")
                    cache.set(key="restart_listener", value=True)
                except NoLongerAvailableException:
                    latest_block_number = self.find_start_ledger(lower_bound=latest_block and latest_block.number or 0)
                except RestartListenerException:
                    pass
                else:
                    latest_block_number += 1

                self.sleep(start_time=start_time)


soroban_service = SorobanService()
