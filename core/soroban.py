import base64
import binascii
import json
import os
import time
from collections import defaultdict
from functools import wraps
from json import JSONDecodeError
from logging import getLogger
from typing import DefaultDict, Optional, Type

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
    TransactionEnvelope,
    scval,
)
from stellar_sdk import xdr as stellar_xdr
from stellar_sdk.exceptions import PrepareTransactionException, SorobanRpcErrorResponse
from stellar_sdk.soroban_rpc import (
    EventFilter,
    GetTransactionStatus,
    Request,
    Response,
    SendTransactionStatus,
    SimulateTransactionResponse,
)
from stellar_sdk.soroban_server import V  # noqa
from stellar_sdk.utils import sha256
from stellar_sdk.xdr import (
    Hash,
    HostFunction,
    HostFunctionType,
    Operation,
    OperationBody,
    OperationResultTr,
    OperationType,
    SCAddress,
    SCAddressType,
    SCErrorType,
    SCSymbol,
    SCVal,
    SCValType,
    SCVec,
    SorobanAuthorizationEntry,
)

from core import models as core_models
from core.event_handler import soroban_event_handler
from multiclique import models as multiclique_models

logger = getLogger("alerts")
slack_logger = getLogger("alerts.slack")


def unpack_sc(val: SCVal | SCVec | SCAddress | SCSymbol | Hash):
    if isinstance(val, SCVec):
        return [unpack_sc(_val) for _val in val.sc_vec]
    elif isinstance(val, SCAddress):
        if val.type == SCAddressType.SC_ADDRESS_TYPE_ACCOUNT:
            return StrKey.encode_ed25519_public_key(val.account_id.account_id.ed25519.uint256)
        else:  # SCAddressType.SC_ADDRESS_TYPE_CONTRACT:
            return StrKey.encode_contract(val.contract_id.hash)
    elif isinstance(val, SCSymbol):
        return val.sc_symbol.decode().strip()
    elif isinstance(val, Hash):
        return base64.b64encode(val.hash).decode()

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
                return val.bytes.sc_bytes.decode().strip().replace("\x00", "")
            except UnicodeDecodeError:
                return StrKey.encode_ed25519_public_key(val.bytes.sc_bytes)
                # todo replace this once protocols are ready
                # str(return val.bytes.sc_bytes)
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
            match err.type:
                case SCErrorType.SCE_CONTRACT:
                    return f"contract_code: {err.contract_code.uint32}"
            try:
                return f"type: {err.type.name}: {err.type.value} | code: {err.code.name}: {err.code.value}"
            except Exception:  # noqa
                pass
        case SCValType.SCV_STRING:
            return val.str.sc_string.decode()

    raise NotImplementedException(f"Unhandled SC(Val)Type: {str(val)}")


def unpack_operation_body(body: OperationBody):
    match body.type:
        case OperationType.INVOKE_HOST_FUNCTION:
            return body.invoke_host_function_op
        case _:
            raise NotImplementedException(f"Unhandled OperationBody: {str(body)}")


def unpack_host_function(func: HostFunction):
    match func.type:
        case HostFunctionType.HOST_FUNCTION_TYPE_INVOKE_CONTRACT:
            return {
                "contract_address": unpack_sc(func.invoke_contract.contract_address),
                "func_name": unpack_sc(func.invoke_contract.function_name),
                "func_args": [unpack_sc(arg) for arg in func.invoke_contract.args],
            }
        case HostFunctionType.HOST_FUNCTION_TYPE_CREATE_CONTRACT:
            return {
                "func_name": "create_contract",
                "contract_id_preimage": {
                    "address": unpack_sc(func.create_contract.contract_id_preimage.from_address.address),
                    "salt": base64.b64encode(
                        func.create_contract.contract_id_preimage.from_address.salt.uint256
                    ).decode(),
                },
                "executable": {"wasm_hash": unpack_sc(func.create_contract.executable.wasm_hash)},
            }
        case _:
            raise NotImplementedException(f"Unhandled HostFunction: {str(func)}")


def unpack_operation_result_tr(val: OperationResultTr):
    match val.type:
        case OperationType.INVOKE_HOST_FUNCTION:
            return val.invoke_host_function_result.code
        case _:
            raise NotImplementedException(f"Unhandled OperationType: {str(val)}")


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
                                    log_and_sleep(
                                        f"SorobanRpcErrorResponse ({exc.code}: {exc.message})", log_exception=True
                                    )
                except Exception:  # noqa E722
                    log_and_sleep("Unexpected error", log_exception=True)

        return action

    return wrap


def update_transaction(
    transaction: multiclique_models.MultiCliqueTransaction,
):
    """
    Args:
        transaction: MultiCliqueTransaction to update

    Returns:
        updated MultiCliqueTransaction

    if the transaction's approval count fulfills its threshold:
        a new, authorized, executable transaction xdr is created
        status is updated to TransactionStatus.EXECUTABLE
    if the transaction's rejection count prevents reaching the threshold:
        status is updated to TransactionStatus.REJECTED
    """
    transaction.refresh_from_db()
    update_fields = []
    if transaction.approvals.count() >= transaction.multiclique_account.default_threshold:
        envelope = soroban_service.prepare_transaction(
            envelope=soroban_service.authorize_transaction(
                obj=transaction.xdr,
                signature_data=soroban_service.create_signature_data(signatures=transaction.approvals.all()),
                nonce=transaction.nonce,
                ledger=transaction.ledger,
            ),
            keypair=Keypair.from_public_key(submitter.address) if (submitter := transaction.submitter) else None,
        )
        transaction.xdr = envelope.to_xdr()
        transaction.status = multiclique_models.TransactionStatus.EXECUTABLE
        update_fields = ["xdr", "status"]
    elif (
        transaction.multiclique_account.signatories.count() - transaction.rejections.count()
        < transaction.multiclique_account.default_threshold
    ):
        transaction.status = multiclique_models.TransactionStatus.REJECTED
        update_fields = ["status"]

    if update_fields:
        transaction.save(update_fields=update_fields)


class RestartListenerException(Exception):
    pass


class SorobanException(Exception):
    msg = None
    ctx = None

    def __init__(self, msg=None, ctx=None):
        self.ctx = ctx or {}
        super().__init__(self.msg if not msg else msg)


class LoggedException(SorobanException):
    def __init__(self, msg=None, ctx=None):
        super().__init__(msg, ctx)
        slack_logger.error(
            f"{self.msg + ': ' if self.msg else ''}{str(msg) if msg else ''} ctx: {json.dumps(self.ctx)}"
        )


class NotImplementedException(LoggedException):
    msg = "NotImplementedException"


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
        json_data = request_body.model_dump_json(by_alias=True)
        data = self._client.post(
            self.server_url,
            json_data=json.loads(json_data),
        )
        try:
            response = Response[response_body_type].model_validate(data.json())
        except JSONDecodeError:
            raise SorobanRpcErrorResponse(code=data.status_code, message=data.text)

        if response.error:
            raise SorobanRpcErrorResponse(
                code=response.error.code, message=response.error.message, data=response.error.data
            )
        assert response.result is not None
        return response.result


class SorobanService(object):
    soroban: RobustSorobanServer = None
    network_passphrase: str = None
    wait_for_txn_interval: int = 1  # seconds
    signature_validity_period: int = None  # ledgers

    @retry("initializing blockchain connection")
    def __init__(self):
        config = self.set_config()
        self.soroban = RobustSorobanServer(server_url=config["blockchain_url"])
        self.network_passphrase = config["network_passphrase"]
        self.signature_validity_period = round(settings.SIGNATURE_VALIDITY_PERIOD / settings.BLOCK_CREATION_INTERVAL)

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.soroban.close()

    def create_preimage_hash(
        self,
        entry: SorobanAuthorizationEntry,
        latest_ledger: int,
    ) -> str:
        auth_addr = entry.credentials.address
        if auth_addr:
            auth_addr.signature_expiration_ledger = stellar_xdr.Uint32(latest_ledger + self.signature_validity_period)
            preimage = stellar_xdr.HashIDPreimage(
                type=stellar_xdr.EnvelopeType.ENVELOPE_TYPE_SOROBAN_AUTHORIZATION,
                soroban_authorization=stellar_xdr.HashIDPreimageSorobanAuthorization(
                    network_id=stellar_xdr.Hash(Network(self.network_passphrase).network_id()),
                    nonce=auth_addr.nonce,
                    signature_expiration_ledger=auth_addr.signature_expiration_ledger,
                    invocation=entry.root_invocation,
                ),
            )
            return base64.b64encode(sha256(preimage.to_xdr_bytes())).decode()

    def _parse_envelope(self, obj: str | TransactionEnvelope) -> (TransactionEnvelope, Operation, str):
        """
        Args:
            obj: XDR str or TransactionEnvelope to parse

        Returns:
            (TransactionEnvelope, Operation, source account id)

        helper function to extract the Operation and source account id from the given TransactionEnvelope or the
        corresponding XDR str
        """
        if isinstance(obj, str):
            try:
                envelope = TransactionEnvelope.from_xdr(xdr=obj, network_passphrase=self.network_passphrase)
            except binascii.Error as err:
                raise InvalidXDRException(ctx={"xdr": obj, "error": str(err)})
        elif isinstance(obj, stellar_xdr.TransactionEnvelope):
            envelope = TransactionEnvelope.from_xdr_object(xdr_object=obj, network_passphrase=self.network_passphrase)
        elif isinstance(obj, TransactionEnvelope):
            envelope = obj
        else:
            raise NotImplementedException(f"_parse_envelope failed, invalid object type: {type(obj)}")

        if len(operations := envelope.transaction.operations) > 1:
            raise NotImplementedException("_parse_envelope failed, multiple txn operations")

        operation = operations[0]
        source_acc = envelope.transaction.source.account_id

        return envelope, operation, source_acc

    def _simulate_transaction(
        self, envelope: TransactionEnvelope, metadata: dict = None
    ) -> SimulateTransactionResponse:
        """
        Args:
            envelope: TransactionEnvelope to simulate
            metadata: metadata used for error logging

        Returns:
            SimulateTransactionResponse

        validation and error handling wrapper around soroban.simulate_transaction
        """
        if metadata is None:
            metadata = {}
        sim_txn = self.soroban.simulate_transaction(transaction_envelope=envelope)
        if sim_txn.error:
            if sim_txn.events:
                events = [stellar_xdr.DiagnosticEvent.from_xdr(event) for event in sim_txn.events]
                event_data = []
                for event in events:
                    body = getattr(event.event.body, f"v{event.event.body.v}")
                    data = unpack_sc(body.data)
                    if isinstance(data, list):
                        if data[0] == "failing with contract error" and len(data) == 2:
                            metadata["contract_error"] = data[1]
                    event_data.append(
                        {
                            "data": data,
                            "topics": [unpack_sc(topic) for topic in body.topics],
                        }
                    )
                metadata["event_data"] = event_data

            raise LoggedException(f"soroban.simulate_transaction failed: {sim_txn.error}", ctx=metadata)

        if sim_txn.results is None:
            raise LoggedException("soroban.simulate_transaction yielded no results", ctx=metadata)

        if len(sim_txn.results[0].auth) > 1:
            raise NotImplementedException(
                "_simulate_transaction failed, multiple SorobanAuthorizationEntries", ctx=metadata
            )

        return sim_txn

    def analyze_transaction(self, obj: str | TransactionEnvelope) -> dict:
        """
        Args:
            obj: XDR str or TransactionEnvelope

        Returns:
            dictionary containing function data
        """
        metadata = {}
        if isinstance(obj, str):
            metadata["xdr"] = obj

        envelope, operation, source_acc = self._parse_envelope(obj)
        sim_txn = self._simulate_transaction(envelope=envelope, metadata={"source_account": source_acc, **metadata})
        nonce = None
        preimage_hash = None
        if sim_txn.results and (auth := sim_txn.results[0].auth):
            auth_entry = SorobanAuthorizationEntry.from_xdr(auth[0])
            preimage_hash = self.create_preimage_hash(
                entry=auth_entry,
                latest_ledger=sim_txn.latest_ledger,
            )
            if auth_entry.credentials.address:
                nonce = auth_entry.credentials.address.nonce.int64

        return {
            **unpack_host_function(operation.host_function),
            "source_acc": source_acc,
            "preimage_hash": preimage_hash,
            "nonce": nonce,
            "ledger": sim_txn.latest_ledger,
        }

    def get_transaction(self, txn_hash, metadata: dict = None):
        """
        Args:
            txn_hash: transaction hash to fetch the transaction for
            metadata: metadata used for error logging

        Returns:
            transaction result
        """
        while (get_txn_res := self.soroban.get_transaction(txn_hash)).status == GetTransactionStatus.NOT_FOUND:
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
                        "topics": [unpack_sc(topic) for topic in body.topics],
                        "data": unpack_sc(body.data),
                    }
                )
            raise LoggedException(
                f"transaction failed: {errs}", ctx={"diagnostic_events": diagnostic_events, **(metadata or {})}
            )

        return unpack_sc(stellar_xdr.TransactionMeta.from_xdr(get_txn_res.result_meta_xdr).v3.soroban_meta.return_value)

    def prepare_transaction(self, envelope: TransactionEnvelope, keypair: Keypair = None, sim_txn=None, sign=False):
        if keypair:
            acc = self.soroban.load_account(keypair.public_key)
            envelope.transaction.source = acc.account
            envelope.transaction.sequence = acc.sequence + 1

        try:
            envelope = self.soroban.prepare_transaction(
                transaction_envelope=envelope, simulate_transaction_response=sim_txn
            )
        except PrepareTransactionException as exc:
            raise LoggedException(f"prepare_transaction failed: {exc.simulate_transaction_response.error}")

        envelope.transaction.fee *= 2
        envelope.transaction.soroban_data.refundable_fee.int64 *= 2
        envelope.transaction.soroban_data.resources.instructions.uint32 *= 2
        if keypair and sign:
            envelope.sign(keypair)
        return envelope

    def send_transaction(self, envelope: TransactionEnvelope, metadata: dict = None):
        """
        Args:
            envelope: TransactionEnvelope to send
            metadata: metadata used for error logging

        Returns:
            transaction result
        """
        send_txn_res = self.soroban.send_transaction(envelope)
        if send_txn_res.status != SendTransactionStatus.PENDING:
            err = stellar_xdr.TransactionResult.from_xdr(send_txn_res.error_result_xdr).result.code.name
            raise LoggedException(f"send_transaction failed: {err}", ctx=metadata or {})

        return self.get_transaction(send_txn_res.hash, metadata=metadata)

    def create_install_contract_transaction(self, source_account_address: str, wasm_id: str) -> TransactionEnvelope:
        """
        Args:
            source_account_address: source account address to create the transaction for
            wasm_id: wasm id to create the transaction for

        Returns:
            an install contract TransactionEnvelope
        """
        try:
            return self.soroban.prepare_transaction(
                (
                    TransactionBuilder(
                        source_account=soroban_service.soroban.load_account(source_account_address),
                        network_passphrase=self.network_passphrase,
                    )
                    .set_timeout(300)
                    .append_create_contract_op(wasm_id=wasm_id, address=source_account_address, salt=os.urandom(32))
                ).build()
            )
        except PrepareTransactionException as exc:
            raise LoggedException(
                f"create_install_contract_txn failed: {exc.message}",
                ctx={"source_account_address": source_account_address, "wasm_id": wasm_id},
            )

    @staticmethod
    def create_signature_data(
        preimage_hash: str = None,
        signers: [Keypair] = None,
        signatures: [multiclique_models.MultiCliqueSignature] = None,
    ) -> SCVal:
        if signatures is None:
            signatures = []
        if preimage_hash and signers:
            for signer in signers:
                signature = signer.sign(base64.b64decode(preimage_hash.encode()))
                public_key = Address(signer.public_key).key
                signatures.append(
                    scval.to_map(
                        {
                            scval.to_symbol("public_key"): scval.to_bytes(public_key),
                            scval.to_symbol("signature"): scval.to_bytes(signature),
                        }
                    )
                )
        else:
            signatures = [
                scval.to_map(
                    {
                        scval.to_symbol("public_key"): scval.to_bytes(Address(sig.signatory_id).key),
                        scval.to_symbol("signature"): scval.to_bytes(base64.b64decode(sig.signature.encode())),
                    }
                )
                for sig in signatures
            ]

        return scval.to_vec(signatures)

    def authorize_transaction(
        self,
        obj: str | TransactionEnvelope,
        signature_data: SCVal,
        sim_txn: SimulateTransactionResponse = None,
        nonce: int = None,
        ledger: int = None,
    ) -> TransactionEnvelope:
        """
        Args:
            obj: XDR str or TransactionEnvelope to add signers for
            signature_data: SCV_VEC[SCV_MAP] containing public keys and signatures
            sim_txn: optional SimulateTransactionResponse to avoid unnecessary simulations
            nonce: nonce used to create the corresponding Preimage
            ledger: ledger used to create the corresponding Preimage

        adds a SorobanAuthorizationEntry to the given TransactionEnvelope
        if a TransactionEnvelope XDR str is given the updated TransactionEnvelope is returned
        """
        envelope, operation, _ = self._parse_envelope(obj)
        if not isinstance(operation, InvokeHostFunction):
            raise NotImplementedException(f"authorize_transaction failed, invalid operation: {type(operation)}")

        if sim_txn is None:
            sim_txn = self._simulate_transaction(envelope=envelope)

        if ledger is None:
            ledger = sim_txn.latest_ledger

        auth_entry = stellar_xdr.SorobanAuthorizationEntry.from_xdr(sim_txn.results[0].auth[0])
        if auth_entry.credentials.type == stellar_xdr.SorobanCredentialsType.SOROBAN_CREDENTIALS_SOURCE_ACCOUNT:
            return envelope

        auth_addr = auth_entry.credentials.address
        if nonce is not None:
            auth_addr.nonce = stellar_xdr.Int64(nonce)
        auth_addr.signature_expiration_ledger = stellar_xdr.Uint32(ledger + self.signature_validity_period)
        auth_addr.signature = signature_data
        operation.auth = [auth_entry]
        return envelope

    def install_contract(self, source_account_address: str, wasm_id: str, keypair: Keypair):
        txn = self.create_install_contract_transaction(source_account_address=source_account_address, wasm_id=wasm_id)
        txn.sign(keypair)
        return self.send_transaction(txn)

    def create_invoke_contract_func_transaction(
        self,
        func_name: str,
        func_args: list,
        source_account: str,
        contract_addr: str = None,
        base_fee=100,
        timeout=300,
    ):
        return (
            TransactionBuilder(
                source_account=self.soroban.load_account(source_account),
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

    def invoke_contract_func(
        self,
        func_name: str,
        func_args: list,
        signers: [Keypair],
        contract_addr: str,
        base_fee=100,
        timeout=300,
    ):
        metadata = {
            "contract_addr": contract_addr,
            "func_name": func_name,
            "func_args": [unpack_sc(arg) for arg in func_args],
        }
        envelope = self.create_invoke_contract_func_transaction(
            func_name=func_name,
            func_args=func_args,
            source_account=signers[0].public_key,
            contract_addr=contract_addr,
            base_fee=base_fee,
            timeout=timeout,
        )
        sim_txn = self._simulate_transaction(envelope=envelope, metadata=metadata)
        if auth := sim_txn.results[0].auth:
            preimage_hash = self.create_preimage_hash(
                entry=stellar_xdr.SorobanAuthorizationEntry.from_xdr(auth[0]),
                latest_ledger=sim_txn.latest_ledger,
            )
            self.authorize_transaction(
                obj=envelope,
                signature_data=self.create_signature_data(preimage_hash=preimage_hash, signers=signers),
                sim_txn=sim_txn,
            )
        return self.send_transaction(
            envelope=self.prepare_transaction(envelope=envelope, keypair=signers[0], sim_txn=sim_txn, sign=True),
            metadata=metadata,
        )

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
                truncate multiclique_policy cascade;
                truncate multiclique_signatory cascade;
                truncate multiclique_signature cascade;
                truncate multiclique_account cascade;
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
            all MultiCliqueAccount IDs,
            all MultiCliquePolicy IDs,
            all Asset IDs

        Returns:
            list of trusted contract IDs
        """
        config = self.set_config()

        trusted_contract_ids = [
            config["core_contract_address"],
            config["votes_contract_address"],
            *core_models.Asset.objects.values_list("address", flat=True),
            *multiclique_models.MultiCliqueAccount.objects.values_list("address", flat=True),
            *multiclique_models.MultiCliquePolicy.objects.values_list("address", flat=True),
        ]
        cache.set(key="trusted_contract_ids", value=trusted_contract_ids)
        return trusted_contract_ids

    @staticmethod
    def set_asset_addresses() -> [str]:
        """
        caches asset addresses at "asset_addresses"
        """
        asset_ids = [*core_models.Asset.objects.values_list("address", flat=True)]
        cache.set(key="asset_addresses", value=asset_ids)
        return asset_ids

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
