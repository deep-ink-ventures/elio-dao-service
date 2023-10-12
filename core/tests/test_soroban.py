import base64
from unittest.mock import Mock, call, patch

from ddt import data, ddt
from django.conf import settings
from django.core.cache import cache
from django.db import IntegrityError, connection
from django.test import override_settings
from stellar_sdk import Keypair, StrKey
from stellar_sdk.client.response import Response
from stellar_sdk.exceptions import SorobanRpcErrorResponse
from stellar_sdk.soroban_rpc import EventFilter
from stellar_sdk.xdr import (
    AccountID,
    Hash,
    Int32,
    Int64,
    Int128Parts,
    PublicKey,
    PublicKeyType,
    SCAddress,
    SCAddressType,
    SCBytes,
    SCMap,
    SCMapEntry,
    SCNonceKey,
    SCSymbol,
    SCVal,
    SCValType,
    SCVec,
    Uint32,
    Uint64,
    UInt128Parts,
    Uint256,
)

from core import models
from core.soroban import (
    NoLongerAvailableException,
    NotImplementedException,
    OutOfSyncException,
    RestartListenerException,
    RobustSorobanServer,
    retry,
    soroban_service,
    unpack_sc,
)
from core.tests.testcases import IntegrationTestCase
from multiclique import models as multiclique_models


class BreakRetry(Exception):
    pass


@ddt
class SorobanTest(IntegrationTestCase):
    @data(
        # input, expected output
        (SCVal(SCValType.SCV_BOOL, b=True), True),
        (SCVal(SCValType.SCV_VOID), None),
        (SCVal(SCValType.SCV_SYMBOL, sym=SCSymbol(sc_symbol="AbC".encode())), "AbC"),
        (SCVal(SCValType.SCV_BYTES, bytes=SCBytes(sc_bytes="AbC\n".encode())), "AbC"),
        (
            SCVal(
                SCValType.SCV_BYTES,
                bytes=SCBytes(
                    sc_bytes=StrKey.decode_ed25519_public_key(
                        data="GBK3WFZRUY5KZTXCYN4WZ5I6AZLMIF5YAWUIKWP6W254NZLTR5LLJGE2"
                    )
                ),
            ),
            "GBK3WFZRUY5KZTXCYN4WZ5I6AZLMIF5YAWUIKWP6W254NZLTR5LLJGE2",
        ),
        (
            SCVal(
                SCValType.SCV_ADDRESS,
                address=SCAddress(
                    type=SCAddressType(SCAddressType.SC_ADDRESS_TYPE_ACCOUNT),
                    account_id=AccountID(
                        PublicKey(
                            type=PublicKeyType(PublicKeyType.PUBLIC_KEY_TYPE_ED25519), ed25519=Uint256("AbC".encode())
                        )
                    ),
                ),
            ),
            "GBAWEQ43CM",
        ),
        (
            SCVal(
                SCValType.SCV_ADDRESS,
                address=SCAddress(
                    type=SCAddressType(SCAddressType.SC_ADDRESS_TYPE_CONTRACT), contract_id=Hash(hash="AbC".encode())
                ),
            ),
            "CBAWEQ6VEQ",
        ),
        (SCVal(SCValType.SCV_U32, u32=Uint32(uint32=123)), 123),
        (SCVal(SCValType.SCV_I32, i32=Int32(int32=123)), 123),
        (SCVal(SCValType.SCV_U64, u64=Uint64(uint64=123)), 123),
        (SCVal(SCValType.SCV_I64, i64=Int64(int64=123)), 123),
        (SCVal(SCValType.SCV_U128, u128=UInt128Parts(hi=Uint64(uint64=0), lo=Uint64(uint64=123))), 123),
        (SCVal(SCValType.SCV_I128, i128=Int128Parts(hi=Int64(int64=0), lo=Uint64(uint64=123))), 123),
        (
            SCVal(
                SCValType.SCV_MAP,
                map=SCMap(
                    sc_map=[
                        SCMapEntry(
                            key=SCVal(SCValType.SCV_SYMBOL, sym=SCSymbol(sc_symbol="a".encode())),
                            val=SCVal(SCValType.SCV_SYMBOL, sym=SCSymbol(sc_symbol="b".encode())),
                        ),
                        SCMapEntry(
                            key=SCVal(SCValType.SCV_SYMBOL, sym=SCSymbol(sc_symbol="b".encode())),
                            val=SCVal(SCValType.SCV_BOOL, b=True),
                        ),
                    ]
                ),
            ),
            {"a": "b", "b": True},
        ),
        (
            SCVal(
                SCValType.SCV_VEC,
                vec=SCVec(
                    sc_vec=[
                        SCVal(SCValType.SCV_SYMBOL, sym=SCSymbol(sc_symbol="a".encode())),
                        SCVal(SCValType.SCV_SYMBOL, sym=SCSymbol(sc_symbol="b".encode())),
                        SCVal(SCValType.SCV_BOOL, b=True),
                    ]
                ),
            ),
            ["a", "b", True],
        ),
    )
    def test_unpack_sc(self, case):
        input_value, expected = case

        self.assertEqual(unpack_sc(input_value), expected, input_value)

    @patch("core.soroban.slack_logger")
    def test_unpack_sc_not_implemented(self, slack_logger):
        expected_err_msg = (
            "Unhandled SC(Val)Type: <SCVal [type=21, nonce_key=<SCNonceKey [nonce=<Int64 [int64=123]>]>]>"
        )
        with self.assertRaisesMessage(NotImplementedException, expected_err_msg):
            self.assertIsNone(
                unpack_sc(SCVal(SCValType.SCV_LEDGER_KEY_NONCE, nonce_key=SCNonceKey(nonce=Int64(int64=123))))
            )
        slack_logger.error.assert_called_once_with(f"NotImplementedException: {expected_err_msg} ctx: {'{}'}")

    @patch("core.soroban.slack_logger")
    @patch("core.soroban.logger")
    @patch("core.soroban.time.sleep")
    def test_retry_ahead_of_chain(self, sleep_mock, logger_mock, slack_logger_mock):
        sleep_mock.side_effect = None, None, None, Exception("break retry")

        def func():
            raise SorobanRpcErrorResponse(message="start is after newest ledger", code=0)

        with override_settings(RETRY_DELAYS=(1, 2, 3, 4)), self.assertRaises(OutOfSyncException):
            retry("some description")(func)()

        expected_err_msg = "SorobanRpcErrorResponse (ahead of chain) while some description. Retrying in %ss ..."
        self.assertExactCalls(
            logger_mock.error,
            [*[call(expected_err_msg % i) for i in range(1, 4)], call("Breaking retry.")],
        )
        slack_logger_mock.assert_not_called()

    def test_retry_no_longer_available(self):
        def func():
            raise SorobanRpcErrorResponse(message="start is before oldest ledger", code=0)

        with self.assertRaises(NoLongerAvailableException):
            retry("some description")(func)()

    @patch("core.soroban.slack_logger")
    @patch("core.soroban.time.sleep")
    def test_retry_404(self, sleep_mock, logger_mock):
        sleep_mock.side_effect = None, None, Exception("break retry")

        def func():
            raise SorobanRpcErrorResponse(message="404 Not Found", code=0)

        with override_settings(RETRY_DELAYS=(1, 2, 3)), self.assertRaisesMessage(Exception, "break retry"):
            retry("some description")(func)()

        expected_err_msg = "SorobanRpcErrorResponse (404) while some description. Retrying in %ss ..."
        logger_mock.error.assert_has_calls([call(expected_err_msg % i) for i in range(1, 3)])

    @patch("core.soroban.slack_logger")
    @patch("core.soroban.logger")
    @patch("core.soroban.time.sleep")
    def test_retry_502(self, sleep_mock, logger_mock, slack_logger_mock):
        sleep_mock.side_effect = None, None, Exception("break retry")

        def func():
            raise SorobanRpcErrorResponse(message="wall of text", code=502)

        with override_settings(RETRY_DELAYS=(1, 2, 3)), self.assertRaisesMessage(Exception, "break retry"):
            retry("some description")(func)()

        expected_err_msg = "SorobanRpcErrorResponse (502 Bad Gateway) while some description. Retrying in %ss ..."
        logger_mock.error.assert_has_calls([call(expected_err_msg % i) for i in range(1, 3)])
        slack_logger_mock.assert_not_called()

    @patch("core.soroban.slack_logger")
    @patch("core.soroban.logger")
    @patch("core.soroban.time.sleep")
    def test_retry_503(self, sleep_mock, logger_mock, slack_logger_mock):
        sleep_mock.side_effect = None, None, Exception("break retry")

        def func():
            raise SorobanRpcErrorResponse(message="wall of text", code=503)

        with override_settings(RETRY_DELAYS=(1, 2, 3)), self.assertRaisesMessage(Exception, "break retry"):
            retry("some description")(func)()

        expected_err_msg = (
            "SorobanRpcErrorResponse (503 Service Temporarily Unavailable) while some description. Retrying in %ss ..."
        )
        logger_mock.error.assert_has_calls([call(expected_err_msg % i) for i in range(1, 3)])
        slack_logger_mock.assert_not_called()

    @patch("core.soroban.slack_logger")
    @patch("core.soroban.logger")
    @patch("core.soroban.time.sleep")
    def test_retry_32602(self, sleep_mock, logger_mock, slack_logger_mock):
        sleep_mock.side_effect = None, None, Exception("break retry")

        def func():
            raise SorobanRpcErrorResponse(message="some err", code=-32602)

        cache.set("trusted_contract_ids", ["1", "2"])
        with override_settings(RETRY_DELAYS=(1, 2, 3)), self.assertRaisesMessage(Exception, "break retry"):
            retry("some description")(func)()

        expected_err_msg = (
            "SorobanRpcErrorResponse (some err) "
            "(trusted_contract_ids: ['1', '2']) while some description. Retrying in %ss ..."
        )
        slack_logger_mock.error.assert_has_calls([call(expected_err_msg % i) for i in range(1, 3)])
        logger_mock.assert_not_called()

    @patch("core.soroban.slack_logger")
    @patch("core.soroban.time.sleep")
    def test_retry_other_request_exception(self, sleep_mock, logger_mock):
        sleep_mock.side_effect = None, None, Exception("break retry")

        def func():
            raise SorobanRpcErrorResponse(message="some err", code=0)

        with override_settings(RETRY_DELAYS=(1, 2, 3)), self.assertRaisesMessage(Exception, "break retry"):
            retry("some description")(func)()

        expected_err_msg = "SorobanRpcErrorResponse (some err) while some description. Retrying in %ss ..."
        logger_mock.exception.assert_has_calls([call(expected_err_msg % i) for i in range(1, 3)])

    @patch("core.soroban.slack_logger")
    @patch("core.soroban.time.sleep")
    def test_retry_unexpected_err(self, sleep_mock, logger_mock):
        sleep_mock.side_effect = None, None, Exception("break retry")

        def func():
            raise Exception("roar")

        with override_settings(RETRY_DELAYS=(1, 2, 3)), self.assertRaisesMessage(Exception, "break retry"):
            retry("some description")(func)()

        expected_err_msg = "Unexpected error while some description. Retrying in %ss ..."
        logger_mock.exception.assert_has_calls([call(expected_err_msg % i) for i in range(1, 3)])

    @patch("core.soroban.slack_logger")
    @patch("core.soroban.time.sleep")
    def test_retry_restart_listener(self, sleep_mock, logger_mock):
        cache.set(key="restart_listener", value=True)

        def func():
            raise Exception("roar")

        with override_settings(RETRY_DELAYS=(1, 2, 3)), self.assertRaises(RestartListenerException):
            retry("some description")(func)()

        logger_mock.exception.assert_called_once_with("Unexpected error while some description. Retrying in 1s ...")
        sleep_mock.assert_not_called()

    def test_RobustSorobanServer__post(self):
        client_mock = Mock()
        client_mock.post.return_value.json.return_value = {
            "id": "asd",
            "jsonrpc": "2.0",
            "result": "asd",
        }
        request_body = Mock()
        server = RobustSorobanServer(server_url="some url", client=client_mock)

        res = server._post(request_body=request_body, response_body_type=str)

        self.assertEqual(res, "asd")

    def test_RobustSorobanServer__post_error(self):
        client_mock = Mock()
        client_mock.post.return_value.json.return_value = {
            "id": "asd",
            "jsonrpc": "2.0",
            "error": {"code": -32600, "message": "start is after newest ledger"},
        }
        request_body = Mock()
        server = RobustSorobanServer(server_url="some url", client=client_mock)

        with self.assertRaises(SorobanRpcErrorResponse):
            server._post(request_body=request_body, response_body_type=str)

    def test_RobustSorobanServer__post_json_err(self):
        client_mock = Mock()
        client_mock.post.return_value = Response(
            headers={
                "Connection": "keep-alive",
                "Content-Length": "13",
                "Content-Type": "text/plain; charset=utf-8",
                "Server": "awselb/2.0",
            },
            status_code=404,
            text="404 Not Found",
            url="some url",
        )
        request_body = Mock()
        server = RobustSorobanServer(server_url="some url", client=client_mock)

        with self.assertRaisesMessage(SorobanRpcErrorResponse, "404 Not Found"):
            server._post(request_body=request_body, response_body_type=str)

    @patch("core.soroban.SorobanServer.close")
    def test___exit__(self, close_mock):
        soroban_service.__exit__(None, None, None)

        close_mock.assert_called_once_with()

    def test_verify(self):
        challenge_token = "something_to_sign"
        keypair = Keypair.random()
        cache.set(key=keypair.public_key, value=challenge_token, timeout=1)
        signature = base64.b64encode(keypair.sign(data=challenge_token.encode())).decode()

        self.assertTrue(
            soroban_service.verify(
                address=keypair.public_key, challenge_address=keypair.public_key, signature=signature
            )
        )

    def test_verify_differing_challenge_address(self):
        challenge_token = "something_to_sign"
        challenge_addr = "some_addr"
        keypair = Keypair.random()
        cache.set(key=challenge_addr, value=challenge_token, timeout=1)
        signature = base64.b64encode(keypair.sign(data=challenge_token.encode())).decode()

        self.assertTrue(
            soroban_service.verify(address=keypair.public_key, challenge_address=challenge_addr, signature=signature)
        )

    def test_verify_fail(self):
        challenge_token = "something_to_sign"
        keypair = Keypair.random()
        cache.set(key=keypair.public_key, value=challenge_token, timeout=1)
        signature = "wrong"

        self.assertFalse(
            soroban_service.verify(
                address=keypair.public_key, challenge_address=keypair.public_key, signature=signature
            )
        )

    def test_verify_no_key(self):
        challenge_token = "something_to_sign"
        keypair = Keypair.random()
        signature = base64.b64encode(keypair.sign(data=challenge_token.encode())).decode()

        self.assertFalse(
            soroban_service.verify(
                address=keypair.public_key, challenge_address=keypair.public_key, signature=signature
            )
        )

    @patch("core.soroban.time.time")
    @patch("core.soroban.time.sleep")
    def test_sleep_longer_than_block_creation_interval(self, sleep_mock, time_mock):
        start_time = 10
        time_mock.return_value = start_time + settings.BLOCK_CREATION_INTERVAL

        soroban_service.sleep(start_time=start_time)
        sleep_mock.assert_not_called()

    @patch("core.soroban.time.time")
    @patch("core.soroban.time.sleep")
    def test_sleep_shorter_than_block_creation_interval(self, sleep_mock, time_mock):
        start_time = 10
        time_mock.return_value = start_time + settings.BLOCK_CREATION_INTERVAL - 1

        soroban_service.sleep(start_time=start_time)
        sleep_mock.called_once_with(1)

    @patch("core.soroban.SorobanService.sleep")
    @patch("core.soroban.slack_logger")
    def test_clear_db_and_cache(self, logger_mock, sleep_mock):
        models.Contract.objects.create(id="c1")
        models.Account.objects.create(address="acc1")
        models.Dao.objects.create(id="dao1", contract_id="c1", name="dao1 name", owner_id="acc1")
        models.Asset.objects.create(address="a1", owner_id="acc1", dao_id="dao1", total_supply=100)
        models.AssetHolding.objects.create(asset_id="a1", owner_id="acc1", balance=100)
        models.Proposal.objects.create(
            id="prop1",
            dao_id="dao1",
            metadata_url="url1",
            metadata_hash="hash1",
            metadata={"a": 1},
            birth_block_number=10,
        )
        models.Governance.objects.create(
            dao_id="dao1",
            proposal_duration=1,
            proposal_token_deposit=2,
            min_threshold_configuration=3,
            type=models.GovernanceType.MAJORITY_VOTE,
        )
        models.Vote.objects.create(voter_id="acc1", proposal_id="prop1", in_favor=True, voting_power=10)
        models.ProposalReport.objects.create(proposal_id="prop1", reason="good reason")
        models.Block.objects.create(number=1)
        multiclique_models.MultiCliquePolicy.objects.create(address="POL1", name="pol1")
        multiclique_models.MultiCliqueSignatory.objects.create(address="SIG1")
        multiclique_models.MultiCliqueSignature.objects.create(signature="sig1", signatory_id="SIG1")
        multiclique_models.MultiCliqueAccount.objects.create(address="ACC1", default_threshold=1, policy_id="POL1")
        multiclique_models.MultiCliqueTransaction.objects.create(xdr="xdr", multiclique_account_id="ACC1")

        with connection.cursor() as cursor:
            cursor.execute("SET CONSTRAINTS ALL IMMEDIATE;")
        cache.set(key="some_key", value=1)

        with self.assertNumQueries(1):
            soroban_service.clear_db_and_cache(start_time=1)

        sleep_mock.assert_called_once_with(start_time=1)
        logger_mock.info.assert_called_once_with(
            "Service and chain are out of sync! Recreating DB, clearing cache, restarting listener..."
        )
        self.assertIsNone(cache.get(key="some_key"))
        self.assertTrue(cache.get(key="restart_listener"))
        for model in (
            models.Block,
            models.Contract,
            models.Account,
            models.Dao,
            models.Asset,
            models.AssetHolding,
            models.Proposal,
            models.ProposalReport,
            models.Vote,
            models.Governance,
            multiclique_models.MultiCliqueAccount,
            multiclique_models.MultiCliquePolicy,
            multiclique_models.MultiCliqueSignatory,
            multiclique_models.MultiCliqueSignature,
            multiclique_models.MultiCliqueTransaction,
        ):
            self.assertListEqual(list(model.objects.all()), [])

    @patch("core.soroban.slack_logger")
    def test_clear_db_and_cache_new_config(self, slack_logger):
        soroban_service.set_config(
            data={
                "core_contract_address": "a",
                "votes_contract_address": "b",
                "assets_wasm_hash": "e",
                "blockchain_url": "f",
                "network_passphrase": "g",
                "multiclique_wasm_hash": "h",
                "policy_wasm_hash": "i",
            }
        )

        with self.assertNumQueries(1):
            soroban_service.clear_db_and_cache(
                start_time=1,
                new_config={
                    "core_contract_address": "1",
                    "votes_contract_address": "2",
                },
            )
        self.assertEqual(
            soroban_service.set_config(),
            {
                "core_contract_address": "1",
                "votes_contract_address": "2",
                "assets_wasm_hash": "some_assets_wasm_hash",
                "blockchain_url": "some_blockchain_url",
                "network_passphrase": "some_network_passphrase",
                "multiclique_wasm_hash": "some_multiclique_wasm_hash",
                "policy_wasm_hash": "some_policy_wasm_hash",
            },
        )
        slack_logger.info.assert_called_once_with(
            "Service and chain are out of sync! Recreating DB, clearing cache, restarting listener..."
        )

    @data(
        # input_data, current_cache, expected_res
        # no input, no cache
        (
            None,
            None,
            {
                "core_contract_address": "a",
                "votes_contract_address": "b",
                "assets_wasm_hash": "e",
                "blockchain_url": "f",
                "network_passphrase": "g",
                "multiclique_wasm_hash": "h",
                "policy_wasm_hash": "i",
            },
        ),
        # no input, existing cache
        (
            None,
            {
                "core_contract_address": 1,
                "votes_contract_address": 2,
                "assets_wasm_hash": 3,
                "blockchain_url": 4,
            },
            {
                "core_contract_address": 1,
                "votes_contract_address": 2,
                "assets_wasm_hash": 3,
                "blockchain_url": 4,
                "network_passphrase": "g",
                "multiclique_wasm_hash": "h",
                "policy_wasm_hash": "i",
            },
        ),
        # input overwrites cache
        (
            {
                "core_contract_address": "a1",
                "votes_contract_address": "a2",
            },
            {
                "core_contract_address": 1,
                "votes_contract_address": 2,
                "assets_wasm_hash": 3,
                "blockchain_url": 4,
            },
            {
                "core_contract_address": "a1",
                "votes_contract_address": "a2",
                "assets_wasm_hash": 3,
                "blockchain_url": 4,
                "network_passphrase": "g",
                "multiclique_wasm_hash": "h",
                "policy_wasm_hash": "i",
            },
        ),
    )
    def test_set_config(self, case):
        input_data, current_cache, expected_res = case

        if current_cache:
            cache.set("soroban_config", current_cache)

        with override_settings(
            CORE_CONTRACT_ADDRESS="a",
            VOTES_CONTRACT_ADDRESS="b",
            ASSETS_WASM_HASH="e",
            BLOCKCHAIN_URL="f",
            NETWORK_PASSPHRASE="g",
            MULTICLIQUE_WASM_HASH="h",
            POLICY_WASM_HASH="i",
        ):
            res = soroban_service.set_config(data=input_data)

        self.assertEqual(res, expected_res)
        self.assertEqual(cache.get("soroban_config"), expected_res)

    def test_set_trusted_contract_ids(self):
        models.Account.objects.create(address="acc1")
        models.Account.objects.create(address="acc2")
        models.Contract.objects.create(id="c1")
        models.Contract.objects.create(id="c2")
        models.Dao.objects.create(id="d1", contract_id="c1", owner_id="acc1")
        models.Dao.objects.create(id="d2", contract_id="c2", owner_id="acc2")
        models.Asset.objects.create(address="a1", dao_id="d1", owner_id="acc1", total_supply=0)
        models.Asset.objects.create(address="a2", dao_id="d2", owner_id="acc2", total_supply=0)
        multiclique_models.MultiCliquePolicy.objects.create(address="POL1", name="pol1")
        multiclique_models.MultiCliquePolicy.objects.create(address="POL2", name="pol2")
        multiclique_models.MultiCliqueAccount.objects.create(address="ACC1")
        multiclique_models.MultiCliqueAccount.objects.create(address="ACC2")

        expected_ids = [
            "CDLUQRW6EXSX4SPXC4WTC3SD5KZE2BHDKPMMKJR4FOPGED4NPKKZ4C4Q",
            "CAPYKFOCLMWWLZRHF65RNARHTMALMBNUPT3EITOEGRZ6TYSA3BV43WMV",
            "a1",
            "a2",
            "ACC1",
            "ACC2",
            "POL1",
            "POL2",
        ]

        ids = soroban_service.set_trusted_contract_ids()

        self.assertEqual(ids, expected_ids)
        self.assertEqual(cache.get("trusted_contract_ids"), expected_ids)

    @data(
        # start, end, guess
        (0, 15, 5),
        (10, 15, 5),
        (10, 15, 9),
        (10, 15, 10),
        (10, 15, 11),
        (10, 15, 15),
        (10, 15, 16),
        (10, 15, 20),
        (10, 15, 100),
    )
    @patch("core.soroban.SorobanServer.get_events")
    @patch("core.soroban.logger")
    def test_find_start_ledger(self, case, _, get_events_mock):
        start, end, guess = case

        def get_events(start_ledger):
            if start_ledger < start:
                raise SorobanRpcErrorResponse(0, message="start is before oldest ledger")
            elif start_ledger > end:
                raise SorobanRpcErrorResponse(0, message="start is after newest ledger")
            return "smth"

        get_events_mock.side_effect = get_events

        with override_settings(SOROBAN_START_LEDGER=guess):
            self.assertEqual(soroban_service.find_start_ledger(), start)
        self.assertLess(get_events_mock.call_count, 10)

    @patch("core.soroban.SorobanServer.get_events")
    def test_find_start_ledger_raises(self, get_events_mock):
        get_events_mock.side_effect = SorobanRpcErrorResponse(message="roar", code=0)

        with self.assertRaisesMessage(SorobanRpcErrorResponse, "roar"):
            soroban_service.find_start_ledger()

    def test_get_events_filters(self):
        cache.set(
            "trusted_contract_ids",
            [
                b"d74846de25e57e49f7172d316e43eab24d04e353d8c5263c2b9e620f8d7a959e",
                b"1f8515c25b2d65e6272fbb1682279b00b605b47cf6444dc43473e9e240d86bcd",
                "a1",
                "a2",
                "a3",
                "a4",
                None,
            ],
        )
        expected_filters = [
            EventFilter(
                contractIds=[
                    b"d74846de25e57e49f7172d316e43eab24d04e353d8c5263c2b9e620f8d7a959e",
                    b"1f8515c25b2d65e6272fbb1682279b00b605b47cf6444dc43473e9e240d86bcd",
                    "a1",
                    "a2",
                    "a3",
                ]
            ),
            EventFilter(
                contractIds=[
                    "a4",
                ]
            ),
        ]

        self.assertEqual(soroban_service.get_events_filters(), expected_filters)

    @patch("core.soroban.SorobanServer.get_events")
    def test_fetch_event_data_no_events(self, get_events_mock):
        get_events_mock.return_value = Mock(latest_ledger=20, events=[])

        res = soroban_service.fetch_event_data(start_ledger=10)

        self.assertEqual(res, 20)
        get_events_mock.assert_called_once_with(
            start_ledger=10,
            filters=[
                EventFilter(
                    contractIds=[
                        "CDLUQRW6EXSX4SPXC4WTC3SD5KZE2BHDKPMMKJR4FOPGED4NPKKZ4C4Q",
                        "CAPYKFOCLMWWLZRHF65RNARHTMALMBNUPT3EITOEGRZ6TYSA3BV43WMV",
                    ],
                )
            ],
            limit=10000,
        )

    @patch("core.event_handler.logger")
    @patch("core.soroban.SorobanServer.get_events")
    def test_fetch_event_data_and_execute(self, get_events_mock, logger_mock):
        get_events_mock.return_value = Mock(
            latest_ledger=200,
            events=[
                Mock(
                    id="event1",
                    contract_id="c1",
                    ledger=1,
                    topic=[
                        SCVal(SCValType.SCV_SYMBOL, sym=SCSymbol(sc_symbol="DAO".encode())).to_xdr(),
                        SCVal(SCValType.SCV_SYMBOL, sym=SCSymbol(sc_symbol="created".encode())).to_xdr(),
                    ],
                    value=Mock(
                        xdr=SCVal(
                            SCValType.SCV_MAP,
                            map=SCMap(
                                sc_map=[
                                    SCMapEntry(
                                        key=SCVal(SCValType.SCV_SYMBOL, sym=SCSymbol(sc_symbol="dao_id".encode())),
                                        val=SCVal(SCValType.SCV_SYMBOL, sym=SCSymbol(sc_symbol="DIV".encode())),
                                    ),
                                    SCMapEntry(
                                        key=SCVal(SCValType.SCV_SYMBOL, sym=SCSymbol(sc_symbol="dao_name".encode())),
                                        val=SCVal(
                                            SCValType.SCV_SYMBOL, sym=SCSymbol(sc_symbol="Deep Ink Ventures".encode())
                                        ),
                                    ),
                                    SCMapEntry(
                                        key=SCVal(SCValType.SCV_SYMBOL, sym=SCSymbol(sc_symbol="owner_id".encode())),
                                        val=SCVal(SCValType.SCV_SYMBOL, sym=SCSymbol(sc_symbol="acc1".encode())),
                                    ),
                                ]
                            ),
                        ).to_xdr()
                    ),
                ),
                Mock(
                    id="event1",
                    contract_id="c2",
                    ledger=2,
                    topic=[
                        SCVal(SCValType.SCV_SYMBOL, sym=SCSymbol(sc_symbol="DAO".encode())).to_xdr(),
                        SCVal(SCValType.SCV_SYMBOL, sym=SCSymbol(sc_symbol="created".encode())).to_xdr(),
                    ],
                    value=Mock(
                        xdr=SCVal(
                            SCValType.SCV_MAP,
                            map=SCMap(
                                sc_map=[
                                    SCMapEntry(
                                        key=SCVal(SCValType.SCV_SYMBOL, sym=SCSymbol(sc_symbol="dao_id".encode())),
                                        val=SCVal(SCValType.SCV_SYMBOL, sym=SCSymbol(sc_symbol="DIV 2".encode())),
                                    ),
                                    SCMapEntry(
                                        key=SCVal(SCValType.SCV_SYMBOL, sym=SCSymbol(sc_symbol="dao_name".encode())),
                                        val=SCVal(
                                            SCValType.SCV_SYMBOL, sym=SCSymbol(sc_symbol="Deep Ink Ventures 2".encode())
                                        ),
                                    ),
                                    SCMapEntry(
                                        key=SCVal(SCValType.SCV_SYMBOL, sym=SCSymbol(sc_symbol="owner_id".encode())),
                                        val=SCVal(SCValType.SCV_SYMBOL, sym=SCSymbol(sc_symbol="acc2".encode())),
                                    ),
                                ]
                            ),
                        ).to_xdr()
                    ),
                ),
            ],
        )
        expected_blocks = [
            models.Block(
                number=1,
                executed=True,
                event_data=[
                    [
                        "c1",
                        "event1",
                        ["DAO", "created"],
                        {"dao_id": "DIV", "dao_name": "Deep Ink Ventures", "owner_id": "acc1"},
                    ]
                ],
            ),
            models.Block(
                number=2,
                executed=True,
                event_data=[
                    [
                        "c2",
                        "event1",
                        ["DAO", "created"],
                        {"dao_id": "DIV 2", "dao_name": "Deep Ink Ventures 2", "owner_id": "acc2"},
                    ]
                ],
            ),
        ]
        expected_accounts = [models.Account(address="acc1"), models.Account(address="acc2")]
        expected_daos = [
            models.Dao(id="DIV", contract_id="c1", name="Deep Ink Ventures", owner_id="acc1", creator_id="acc1"),
            models.Dao(id="DIV2", contract_id="c2", name="Deep Ink Ventures 2", owner_id="acc2", creator_id="acc2"),
        ]

        res = soroban_service.fetch_event_data(start_ledger=10)

        self.assertEqual(res, 2)
        self.assertModelsEqual(models.Account.objects.all(), expected_accounts)
        self.assertModelsEqual(
            models.Block.objects.all(), expected_blocks, ignore_fields=["id", "created_at", "updated_at"]
        )
        self.assertModelsEqual(
            models.Dao.objects.all(), expected_daos, ignore_fields=["id", "created_at", "updated_at"]
        )
        get_events_mock.assert_called_once_with(
            start_ledger=10,
            filters=[
                EventFilter(
                    contractIds=[
                        "CDLUQRW6EXSX4SPXC4WTC3SD5KZE2BHDKPMMKJR4FOPGED4NPKKZ4C4Q",
                        "CAPYKFOCLMWWLZRHF65RNARHTMALMBNUPT3EITOEGRZ6TYSA3BV43WMV",
                    ],
                )
            ],
            limit=10000,
        )
        logger_mock.assert_has_calls(
            [
                call.info("Executing event_data... Block number: 1"),
                call.info(
                    "Contract ID: c1 | Event ID: event1 | Topics: ['DAO', 'created'] | "
                    "Values: {'dao_id': 'DIV', 'dao_name': 'Deep Ink Ventures', 'owner_id': 'acc1'}"
                ),
                call.info("Executing event_data... Block number: 2"),
                call.info(
                    "Contract ID: c2 | Event ID: event1 | Topics: ['DAO', 'created'] | "
                    "Values: {'dao_id': 'DIV 2', 'dao_name': 'Deep Ink Ventures 2', 'owner_id': 'acc2'}"
                ),
            ]
        )

    @patch("core.soroban.SorobanService.find_start_ledger")
    @patch("core.soroban.SorobanService.fetch_event_data")
    @patch("core.event_handler.logger")
    @patch("core.soroban.logger")
    @patch("core.soroban.time.sleep")
    def test_listen_existing_block(
        self, sleep_mock, soroban_logger, event_handler_logger, fetch_event_data_mock, find_start_ledger_mock
    ):
        sleep_mock.side_effect = BreakRetry
        find_start_ledger_mock.return_value = 123
        block = models.Block.objects.create(number=0)

        with self.assertRaises(BreakRetry):
            soroban_service.listen()

        block.refresh_from_db()
        self.assertTrue(block.executed)
        event_handler_logger.info.assert_called_once_with("Executing event_data... Block number: 0")
        soroban_logger.info.assert_called_once_with("Listening... Latest block number: 1")
        find_start_ledger_mock.assert_not_called()
        fetch_event_data_mock.assert_called_once_with(start_ledger=1)

    @patch("core.soroban.SorobanService.find_start_ledger")
    @patch("core.soroban.SorobanService.fetch_event_data")
    @patch("core.soroban.logger")
    @patch("core.soroban.time.sleep")
    def test_listen_all_blocks_executed(self, sleep_mock, logger_mock, fetch_event_data_mock, find_start_ledger_mock):
        sleep_mock.side_effect = BreakRetry
        find_start_ledger_mock.return_value = 123
        models.Block.objects.create(number=0, executed=True)

        with self.assertRaises(BreakRetry):
            soroban_service.listen()

        logger_mock.info.assert_called_once_with("Listening... Latest block number: 1")
        find_start_ledger_mock.assert_not_called()
        fetch_event_data_mock.assert_called_once_with(start_ledger=1)

    @patch("core.soroban.SorobanService.find_start_ledger")
    @patch("core.soroban.SorobanService.fetch_event_data")
    @patch("core.soroban.logger")
    @patch("core.soroban.time.sleep")
    def test_listen_no_blocks(self, sleep_mock, logger_mock, fetch_event_data_mock, find_start_ledger_mock):
        sleep_mock.side_effect = BreakRetry
        find_start_ledger_mock.return_value = 123

        with self.assertRaises(BreakRetry):
            soroban_service.listen()

        self.assertIsNone(cache.get(key="restart_listener"))
        logger_mock.info.assert_called_once_with("Listening... Latest block number: 123")
        find_start_ledger_mock.assert_called_once_with()
        fetch_event_data_mock.assert_called_once_with(start_ledger=123)

    @patch("core.soroban.SorobanService.clear_db_and_cache")
    @patch("core.soroban.SorobanService.find_start_ledger")
    @patch("core.soroban.SorobanService.fetch_event_data")
    @patch("core.soroban.slack_logger")
    @patch("core.soroban.logger")
    @patch("core.soroban.time.sleep")
    @patch("core.soroban.time.time")
    def test_listen_IntegrityError(
        self,
        time_mock,
        sleep_mock,
        logger_mock,
        slack_logger_mock,
        fetch_event_data_mock,
        find_start_ledger_mock,
        clear_db_and_cache_mock,
    ):
        time_mock.return_value = 10
        sleep_mock.side_effect = BreakRetry
        fetch_event_data_mock.side_effect = IntegrityError
        models.Block.objects.create(number=0, executed=True)
        expected_config = {
            "core_contract_address": "a",
            "votes_contract_address": "b",
            "assets_wasm_hash": "some_assets_wasm_hash",
            "blockchain_url": "some_blockchain_url",
            "network_passphrase": "some_network_passphrase",
            "multiclique_wasm_hash": "some_multiclique_wasm_hash",
            "policy_wasm_hash": "some_policy_wasm_hash",
        }
        soroban_service.set_config(
            data={
                "core_contract_address": "a",
                "votes_contract_address": "b",
            }
        )

        with self.assertRaises(BreakRetry):
            soroban_service.listen()

        logger_mock.info.assert_called_once_with("Listening... Latest block number: 1")
        find_start_ledger_mock.assert_called_once_with()
        slack_logger_mock.exception.assert_called_once_with("IntegrityError")
        clear_db_and_cache_mock.assert_called_once_with(start_time=10, new_config=expected_config)
        fetch_event_data_mock.assert_called_once_with(start_ledger=1)
        self.assertEqual(soroban_service.set_config(), expected_config)

    @patch("core.soroban.SorobanService.fetch_event_data")
    @patch("core.soroban.slack_logger")
    @patch("core.soroban.logger")
    @patch("core.soroban.time.sleep")
    @patch("core.soroban.time.time")
    def test_listen_OutOfSyncException(
        self,
        time_mock,
        sleep_mock,
        logger_mock,
        slack_logger_mock,
        fetch_event_data_mock,
    ):
        time_mock.return_value = 10
        sleep_mock.side_effect = BreakRetry
        fetch_event_data_mock.side_effect = OutOfSyncException
        models.Block.objects.create(number=0, executed=True)

        with self.assertRaises(BreakRetry):
            soroban_service.listen()

        logger_mock.info.assert_called_once_with("Listening... Latest block number: 1")
        slack_logger_mock.exception.assert_called_once_with("OutOfSyncException")
        fetch_event_data_mock.assert_called_once_with(start_ledger=1)
        self.assertTrue(cache.get(key="restart_listener"))

    @patch("core.soroban.SorobanService.clear_db_and_cache")
    @patch("core.soroban.SorobanService.find_start_ledger")
    @patch("core.soroban.SorobanService.fetch_event_data")
    @patch("core.soroban.logger")
    @patch("core.soroban.time.sleep")
    @patch("core.soroban.time.time")
    def test_listen_NoLongerAvailableException(
        self, time_mock, sleep_mock, logger_mock, fetch_event_data_mock, find_start_ledger_mock, clear_db_and_cache_mock
    ):
        time_mock.return_value = 10
        sleep_mock.side_effect = BreakRetry
        fetch_event_data_mock.side_effect = NoLongerAvailableException
        models.Block.objects.create(number=3, executed=True)

        with self.assertRaises(BreakRetry):
            soroban_service.listen()

        logger_mock.info.assert_called_once_with("Listening... Latest block number: 4")
        find_start_ledger_mock.assert_called_once_with(lower_bound=3)
        clear_db_and_cache_mock.assert_not_called()
        fetch_event_data_mock.assert_called_once_with(start_ledger=4)

    @patch("core.soroban.SorobanService.clear_db_and_cache")
    @patch("core.soroban.SorobanService.find_start_ledger")
    @patch("core.soroban.SorobanService.fetch_event_data")
    @patch("core.soroban.logger")
    @patch("core.soroban.time.sleep")
    @patch("core.soroban.time.time")
    def test_listen_RestartListenerException(
        self, time_mock, sleep_mock, logger_mock, fetch_event_data_mock, find_start_ledger_mock, clear_db_and_cache_mock
    ):
        time_mock.return_value = 10
        sleep_mock.side_effect = BreakRetry
        fetch_event_data_mock.side_effect = RestartListenerException
        models.Block.objects.create(number=3, executed=True)

        with self.assertRaises(BreakRetry):
            soroban_service.listen()

        logger_mock.info.assert_called_once_with("Listening... Latest block number: 4")
        fetch_event_data_mock.assert_called_once_with(start_ledger=4)
        find_start_ledger_mock.assert_not_called()
        clear_db_and_cache_mock.assert_not_called()

    @patch("core.soroban.SorobanService.clear_db_and_cache")
    @patch("core.soroban.SorobanService.find_start_ledger")
    @patch("core.soroban.SorobanService.fetch_event_data")
    @patch("core.soroban.logger")
    @patch("core.soroban.time.sleep")
    @patch("core.soroban.time.time")
    def test_listen_flow(
        self, time_mock, sleep_mock, logger_mock, fetch_event_data_mock, find_start_ledger_mock, clear_db_and_cache_mock
    ):
        time_mock.return_value = 10
        sleep_mock.side_effect = (0, BreakRetry)
        fetch_event_data_mock.side_effect = (50, 100)
        models.Block.objects.create(number=3, executed=True)
        cache.set(key="restart_listener", value=True)

        with self.assertRaises(BreakRetry):
            soroban_service.listen()

        self.assertIsNone(cache.get(key="restart_listener"))
        logger_mock.info.assert_has_calls(
            [
                call("Listening... Latest block number: 4"),
                call("Listening... Latest block number: 51"),
            ]
        )
        find_start_ledger_mock.assert_not_called()
        clear_db_and_cache_mock.assert_not_called()
        fetch_event_data_mock.assert_has_calls(
            [
                call(start_ledger=4),
                call(start_ledger=51),
            ]
        )

    @patch("core.soroban.SorobanService.find_start_ledger")
    @patch("core.soroban.SorobanService.fetch_event_data")
    @patch("core.soroban.logger")
    @patch("core.soroban.slack_logger")
    @patch("core.soroban.SorobanService.sleep")
    @patch("core.soroban.time.time")
    def test_listen_restarting(
        self,
        time_mock,
        sleep_mock,
        slack_logger_mock,
        logger_mock,
        fetch_event_data_mock,
        find_start_ledger_mock,
    ):
        def side_effect(start_time):
            match start_time:
                case 2:
                    soroban_service.clear_db_and_cache()
                case 3:
                    raise BreakRetry

        time_mock.side_effect = (1, 2, 3)
        sleep_mock.side_effect = side_effect
        fetch_event_data_mock.side_effect = (50, 100, 150)
        models.Block.objects.create(number=3, executed=True)
        cache.set(key="restart_listener", value=True)

        with self.assertRaises(BreakRetry):
            soroban_service.listen()

        self.assertIsNone(cache.get(key="restart_listener"))
        logger_mock.info.assert_has_calls(
            [
                call("Listening... Latest block number: 4"),
                call("Listening... Latest block number: 51"),
            ]
        )
        slack_logger_mock.info.assert_called_once_with(
            "Service and chain are out of sync! Recreating DB, clearing cache, restarting listener..."
        )
        find_start_ledger_mock.assert_called_once_with()
        fetch_event_data_mock.assert_has_calls(
            [
                call(start_ledger=4),
                call(start_ledger=51),
            ]
        )
