import base64
import secrets
from collections.abc import Collection
from functools import partial
from unittest.mock import PropertyMock, patch

from ddt import data, ddt
from django.conf import settings
from django.core.cache import cache
from django.test import override_settings
from django.urls import reverse
from rest_framework.exceptions import ErrorDetail
from rest_framework.status import (
    HTTP_200_OK,
    HTTP_201_CREATED,
    HTTP_400_BAD_REQUEST,
    HTTP_401_UNAUTHORIZED,
    HTTP_403_FORBIDDEN,
)
from stellar_sdk import Keypair

from core import models
from core.tests.testcases import IntegrationTestCase


def wrap_in_pagination_res(results: Collection) -> dict:
    return {"count": len(results), "next": None, "previous": None, "results": results}


expected_dao1_res = {
    "id": "dao1",
    "contract_id": "contract1",
    "name": "dao1 name",
    "creator_id": "acc1",
    "owner_id": "acc1",
    "asset_address": "a1",
    "proposal_duration": 10,
    "proposal_token_deposit": 123,
    "min_threshold_configuration": 50,
    "setup_complete": False,
    "metadata": {"some": "data"},
    "metadata_url": None,
    "metadata_hash": None,
}
expected_dao2_res = {
    "id": "dao2",
    "contract_id": "contract2",
    "name": "dao2 name",
    "creator_id": "acc2",
    "owner_id": "acc2",
    "asset_address": "a2",
    "proposal_duration": 15,
    "proposal_token_deposit": 234,
    "min_threshold_configuration": 45,
    "setup_complete": False,
    "metadata": None,
    "metadata_url": None,
    "metadata_hash": None,
}


@ddt
class CoreViewSetTest(IntegrationTestCase):
    def setUp(self):
        self.challenge_key = secrets.token_hex(64)
        cache.set(key="acc1", value=self.challenge_key, timeout=60)
        models.Account.objects.create(address="acc1")
        models.Account.objects.create(address="acc2")
        models.Account.objects.create(address="acc3")
        models.Account.objects.create(address="acc4")
        models.Contract.objects.create(id="contract1")
        models.Contract.objects.create(id="contract2")
        models.Contract.objects.create(id="contract3")
        models.Contract.objects.create(id="contract4")
        models.Dao.objects.create(
            id="dao1",
            contract_id="contract1",
            name="dao1 name",
            creator_id="acc1",
            owner_id="acc1",
            metadata={"some": "data"},
        )
        models.Governance.objects.create(
            dao_id="dao1", proposal_duration=10, proposal_token_deposit=123, min_threshold_configuration=50
        )
        models.Dao.objects.create(
            id="dao2", contract_id="contract2", name="dao2 name", creator_id="acc2", owner_id="acc2"
        )
        models.Governance.objects.create(
            dao_id="dao2", proposal_duration=15, proposal_token_deposit=234, min_threshold_configuration=45
        )
        models.Asset.objects.create(address="a1", owner_id="acc1", dao_id="dao1", total_supply=1000)
        models.Asset.objects.create(address="a2", owner_id="acc2", dao_id="dao2", total_supply=200)
        models.AssetHolding.objects.create(asset_id="a1", owner_id="acc1", balance=500)
        models.AssetHolding.objects.create(asset_id="a1", owner_id="acc2", balance=300)
        models.AssetHolding.objects.create(asset_id="a1", owner_id="acc3", balance=100)
        models.AssetHolding.objects.create(asset_id="a1", owner_id="acc4", balance=100)
        models.AssetHolding.objects.create(asset_id="a2", owner_id="acc2", balance=200)
        models.Proposal.objects.create(
            id="prop1",
            dao_id="dao1",
            creator_id="acc1",
            metadata_url="url1",
            metadata_hash="hash1",
            metadata={"a": 1},
            birth_block_number=10,
        )
        models.Proposal.objects.create(
            id="prop2",
            dao_id="dao2",
            creator_id="acc2",
            metadata_url="url2",
            metadata_hash="hash2",
            metadata={"a": 2},
            fault="some reason",
            status=models.ProposalStatus.FAULTED,
            birth_block_number=15,
            setup_complete=True,
        )
        models.Vote.objects.create(proposal_id="prop1", voter_id="acc1", in_favor=True, voting_power=500)
        models.Vote.objects.create(proposal_id="prop1", voter_id="acc2", in_favor=True, voting_power=300)
        models.Vote.objects.create(proposal_id="prop1", voter_id="acc3", in_favor=False, voting_power=100)
        models.Vote.objects.create(proposal_id="prop1", voter_id="acc4", voting_power=100)
        models.Vote.objects.create(proposal_id="prop2", voter_id="acc2", in_favor=False, voting_power=200)

    def test_welcome(self):
        expected_res = {"success": True, "message": "Welcome traveler."}
        with self.assertNumQueries(0):
            res = self.client.get(reverse("core-welcome"))

        self.assertDictEqual(res.data, expected_res)

    def test_block_metadata_header(self):
        cache.set(key="current_block_number", value=1)

        with self.assertNumQueries(0):
            res = self.client.get(reverse("core-welcome"))

        self.assertEqual(res.headers["Block-Number"], "1")

    def test_stats(self):
        expected_res = {"account_count": 4, "dao_count": 2, "proposal_count": 2, "vote_count": 4}

        with self.assertNumQueries(4):
            res = self.client.get(reverse("core-stats"))

        self.assertDictEqual(res.data, expected_res)

    def test_config(self):
        cache.set(key="current_block_number", value=123)
        expected_res = {
            "deposit_to_create_dao": settings.DEPOSIT_TO_CREATE_DAO,
            "deposit_to_create_proposal": settings.DEPOSIT_TO_CREATE_PROPOSAL,
            "block_creation_interval": settings.BLOCK_CREATION_INTERVAL,
            "core_contract_address": settings.CORE_CONTRACT_ADDRESS,
            "votes_contract_address": settings.VOTES_CONTRACT_ADDRESS,
            "assets_wasm_hash": settings.ASSETS_WASM_HASH,
            "multiclique_wasm_hash": settings.MULTICLIQUE_WASM_HASH,
            "policy_wasm_hash": settings.POLICY_WASM_HASH,
            "blockchain_url": settings.BLOCKCHAIN_URL,
            "network_passphrase": settings.NETWORK_PASSPHRASE,
            "current_block_number": 123,
            "horizon_server_standalone": "https://node.elio-dao.org/",
            "horizon_server_futurenet": "https://horizon-futurenet.stellar.org/",
            "horizon_server_testnet": "https://horizon-testnet.stellar.org/",
            "horizon_server_mainnet": "https://horizon.stellar.org/",
        }

        with self.assertNumQueries(0):
            res = self.client.get(reverse("core-config"))

        self.assertDictEqual(res.data, expected_res)

    @patch("core.soroban.SorobanService.clear_db_and_cache")
    @patch("core.views.slack_logger")
    def test_update_config(self, slack_logger_mock, clear_db_and_cache_mock):
        cache.clear()

        expected_res = {
            "core_contract_address": "CDLUQRW6EXSX4SPXC4WTC3SD5KZE2BHDKPMMKJR4FOPGED4NPKKZ4C4Q",
            "votes_contract_address": "2",
            "assets_wasm_hash": "some_assets_wasm_hash",
            "multiclique_wasm_hash": "1",
            "policy_wasm_hash": "some_policy_wasm_hash",
            "blockchain_url": "some_blockchain_url",
            "network_passphrase": "some_network_passphrase",
        }
        payload = {
            "multiclique_wasm_hash": "1",
            "votes_contract_address": "2",
            "not": "interesting",
        }

        with self.assertNumQueries(0), override_settings(SLACK_ELIO_URL="some url"):
            res = self.client.patch(
                reverse("core-update-config"),
                data=payload,
                content_type="application/json",
                HTTP_CONFIG_SECRET="much-secure",
            )

        self.assertEqual(res.status_code, HTTP_200_OK)
        self.assertDictEqual(res.json(), expected_res)
        clear_db_and_cache_mock.assert_called_once_with(new_config=expected_res)
        slack_logger_mock.info.assert_called_once_with(
            "New deployment! :happy_sheep:", extra={"channel": "some url", "disable_formatting": True}
        )

    @patch("core.soroban.SorobanService.set_trusted_contract_ids")
    @patch("core.soroban.SorobanService.clear_db_and_cache")
    def test_update_config_401(self, clear_db_and_cache_mock, set_trusted_contract_ids_mock):
        initial_values = {
            "CORE_CONTRACT_ADDRESS": settings.CORE_CONTRACT_ADDRESS,
            "VOTES_CONTRACT_ADDRESS": settings.VOTES_CONTRACT_ADDRESS,
            "ASSETS_WASM_HASH": settings.ASSETS_WASM_HASH,
        }
        input_data = {
            "core_contract_address": "c",
            "votes_contract_address": "v",
            "assets_wasm_hash": "a",
        }

        with self.assertNumQueries(0):
            res = self.client.patch(
                reverse("core-update-config"),
                data={
                    **input_data,
                    "not": "interesting",
                },
                content_type="application/json",
                HTTP_CONFIG_SECRET="wrong",
            )

        self.assertEqual(res.status_code, HTTP_401_UNAUTHORIZED)
        self.assertIsNone(res.data)
        clear_db_and_cache_mock.assert_not_called()
        set_trusted_contract_ids_mock.assert_not_called()
        self.assertEqual(settings.CORE_CONTRACT_ADDRESS, initial_values["CORE_CONTRACT_ADDRESS"])
        self.assertEqual(settings.VOTES_CONTRACT_ADDRESS, initial_values["VOTES_CONTRACT_ADDRESS"])
        self.assertEqual(settings.ASSETS_WASM_HASH, initial_values["ASSETS_WASM_HASH"])

    # todo
    # def test_account_get(self):
    #     expected_balance = {"free": 1, "reserved": 2, "misc_frozen": 3, "fee_frozen": 4}
    #
    #     with patch("substrateinterface.SubstrateInterface"):
    #         from core.substrate import substrate_service
    #
    #         substrate_service.retrieve_account_balance = Mock(return_value=expected_balance)
    #
    #     expected_res = {"address": "acc1", "balance": expected_balance}
    #
    #     with self.assertNumQueries(1):
    #         res = self.client.get(reverse("core-account-detail", kwargs={"pk": "acc1"}))
    #
    #     self.assertDictEqual(res.data, expected_res)

    def test_account_get_list(self):
        expected_res = wrap_in_pagination_res(
            [{"address": "acc1"}, {"address": "acc2"}, {"address": "acc3"}, {"address": "acc4"}]
        )

        with self.assertNumQueries(2):
            res = self.client.get(reverse("core-account-list"))

        self.assertDictEqual(res.data, expected_res)

    def test_dao_get(self):
        with self.assertNumQueries(1):
            res = self.client.get(reverse("core-dao-detail", kwargs={"pk": "dao1"}))

        self.assertDictEqual(res.data, expected_dao1_res)

    def test_dao_get_list(self):
        expected_res = wrap_in_pagination_res([expected_dao1_res, expected_dao2_res])

        with self.assertNumQueries(2):
            res = self.client.get(reverse("core-dao-list"))

        self.assertDictEqual(res.data, expected_res)

    @data(
        # query_params
        {"pk": "dao2"},
        {"owner_id": "acc2"},
        {"name": "dao2 name"},
    )
    def test_dao_list_filter(self, query_params):
        expected_res = wrap_in_pagination_res([expected_dao2_res])

        with self.assertNumQueries(2):
            res = self.client.get(reverse("core-dao-list"), query_params)

        self.assertDictEqual(res.data, expected_res)

    @data(
        # query_params, expected_res
        (
            {"ordering": "id"},
            [
                expected_dao1_res,
                expected_dao2_res,
                {
                    "id": "dao3",
                    "contract_id": "contract3",
                    "name": "3",
                    "creator_id": "acc1",
                    "owner_id": "acc2",
                    "asset_address": None,
                    "proposal_duration": None,
                    "proposal_token_deposit": None,
                    "min_threshold_configuration": None,
                    "setup_complete": True,
                    "metadata": None,
                    "metadata_url": None,
                    "metadata_hash": None,
                },
            ],
        ),
        (
            {"ordering": "name"},
            [
                {
                    "id": "dao3",
                    "contract_id": "contract3",
                    "name": "3",
                    "creator_id": "acc1",
                    "owner_id": "acc2",
                    "asset_address": None,
                    "proposal_duration": None,
                    "proposal_token_deposit": None,
                    "min_threshold_configuration": None,
                    "setup_complete": True,
                    "metadata": None,
                    "metadata_url": None,
                    "metadata_hash": None,
                },
                expected_dao1_res,
                expected_dao2_res,
            ],
        ),
        (
            {"ordering": "owner_id,id"},
            [
                expected_dao1_res,
                expected_dao2_res,
                {
                    "id": "dao3",
                    "contract_id": "contract3",
                    "name": "3",
                    "creator_id": "acc1",
                    "owner_id": "acc2",
                    "asset_address": None,
                    "proposal_duration": None,
                    "proposal_token_deposit": None,
                    "min_threshold_configuration": None,
                    "setup_complete": True,
                    "metadata": None,
                    "metadata_url": None,
                    "metadata_hash": None,
                },
            ],
        ),
    )
    def test_dao_list_ordering(self, case):
        query_params, expected_res = case
        models.Dao.objects.create(
            id="dao3", contract_id="contract3", name="3", creator_id="acc1", owner_id="acc2", setup_complete=True
        )

        expected_res = wrap_in_pagination_res(expected_res)

        with self.assertNumQueries(2):
            res = self.client.get(reverse("core-dao-list"), query_params)

        self.assertDictEqual(res.data, expected_res)

    @data(
        # query_params, expected_res, expected query count
        (
            {"prioritise_owner": "acc2", "ordering": "-name"},
            [
                {
                    "id": "dao4",
                    "contract_id": "contract4",
                    "name": "dao4 name",
                    "creator_id": "acc2",
                    "owner_id": "acc2",
                    "asset_address": "a4",
                    "proposal_duration": None,
                    "proposal_token_deposit": None,
                    "min_threshold_configuration": None,
                    "setup_complete": False,
                    "metadata": None,
                    "metadata_url": None,
                    "metadata_hash": None,
                },
                expected_dao2_res,
                {
                    "id": "dao3",
                    "contract_id": "contract3",
                    "name": "dao3 name",
                    "creator_id": "acc1",
                    "owner_id": "acc1",
                    "asset_address": "a3",
                    "proposal_duration": None,
                    "proposal_token_deposit": None,
                    "min_threshold_configuration": None,
                    "setup_complete": False,
                    "metadata": None,
                    "metadata_url": None,
                    "metadata_hash": None,
                },
                expected_dao1_res,
            ],
            4,
        ),
        (
            {"prioritise_holder": "acc3", "ordering": "-name"},
            [
                {
                    "id": "dao4",
                    "contract_id": "contract4",
                    "name": "dao4 name",
                    "creator_id": "acc2",
                    "owner_id": "acc2",
                    "asset_address": "a4",
                    "proposal_duration": None,
                    "proposal_token_deposit": None,
                    "min_threshold_configuration": None,
                    "setup_complete": False,
                    "metadata": None,
                    "metadata_url": None,
                    "metadata_hash": None,
                },
                {
                    "id": "dao3",
                    "contract_id": "contract3",
                    "name": "dao3 name",
                    "creator_id": "acc1",
                    "owner_id": "acc1",
                    "asset_address": "a3",
                    "proposal_duration": None,
                    "proposal_token_deposit": None,
                    "min_threshold_configuration": None,
                    "setup_complete": False,
                    "metadata": None,
                    "metadata_url": None,
                    "metadata_hash": None,
                },
                expected_dao1_res,
                expected_dao2_res,
            ],
            4,
        ),
        (
            {"prioritise_owner": "acc2", "prioritise_holder": "acc3", "ordering": "name"},
            [
                expected_dao2_res,
                {
                    "id": "dao4",
                    "contract_id": "contract4",
                    "name": "dao4 name",
                    "creator_id": "acc2",
                    "owner_id": "acc2",
                    "asset_address": "a4",
                    "proposal_duration": None,
                    "proposal_token_deposit": None,
                    "min_threshold_configuration": None,
                    "setup_complete": False,
                    "metadata": None,
                    "metadata_url": None,
                    "metadata_hash": None,
                },
                expected_dao1_res,
                {
                    "id": "dao3",
                    "contract_id": "contract3",
                    "name": "dao3 name",
                    "creator_id": "acc1",
                    "owner_id": "acc1",
                    "asset_address": "a3",
                    "proposal_duration": None,
                    "proposal_token_deposit": None,
                    "min_threshold_configuration": None,
                    "setup_complete": False,
                    "metadata": None,
                    "metadata_url": None,
                    "metadata_hash": None,
                },
            ],
            5,
        ),
    )
    def test_dao_list_prioritised(self, case):
        query_params, expected_res, expected_query_count = case
        models.Dao.objects.create(
            id="dao3", contract_id="contract3", name="dao3 name", creator_id="acc1", owner_id="acc1"
        )
        models.Dao.objects.create(
            id="dao4", contract_id="contract4", name="dao4 name", creator_id="acc2", owner_id="acc2"
        )
        models.Asset.objects.create(address="a3", owner_id="acc1", dao_id="dao3", total_supply=100)
        models.Asset.objects.create(address="a4", owner_id="acc2", dao_id="dao4", total_supply=200)
        models.AssetHolding.objects.create(asset_id="a3", owner_id="acc3", balance=100)
        models.AssetHolding.objects.create(asset_id="a4", owner_id="acc3", balance=200)

        expected_res = wrap_in_pagination_res(expected_res)

        with self.assertNumQueries(expected_query_count):
            res = self.client.get(reverse("core-dao-list"), query_params)

        self.assertDictEqual(res.data, expected_res)

    @patch("core.view_utils.MultiQsLimitOffsetPagination.default_limit", PropertyMock(return_value=None))
    def test_dao_list_no_limit(self):
        expected_res = [expected_dao1_res, expected_dao2_res]

        with self.assertNumQueries(2):
            res = self.client.get(reverse("core-dao-list"), {"prioritise_owner": "acc2"})

        self.assertCountEqual(res.data, expected_res)

    def test_dao_challenge(self):
        with self.assertNumQueries(1):
            res = self.client.get(reverse("core-dao-challenge", kwargs={"pk": "dao1"}))

        self.assertEqual(res.data["challenge"], cache.get("acc1"))

    def test_dao_add_metadata(self):
        keypair = Keypair.random()
        cache.set(key=keypair.public_key, value=self.challenge_key, timeout=5)
        signature = base64.b64encode(keypair.sign(data=self.challenge_key.encode())).decode()
        acc = models.Account.objects.create(address=keypair.public_key)
        models.Dao.objects.create(id="DAO1", contract_id="contract1", name="dao1 name", owner=acc)

        with open("core/tests/test_file.jpeg", "rb") as f:
            post_data = {
                "email": "some@email.com",
                "description_short": "short description",
                "description_long": "long description",
                "logo": base64.b64encode(f.read()).decode(),
            }
        expected_res = {
            "metadata": {
                "description_short": "short description",
                "description_long": "long description",
                "email": "some@email.com",
                "images": {
                    "logo": {
                        "content_type": "image/jpeg",
                        "large": {"url": "https://some_storage.some_region.com/DAO1/logo_large.jpeg"},
                        "medium": {"url": "https://some_storage.some_region.com/DAO1/logo_medium.jpeg"},
                        "small": {"url": "https://some_storage.some_region.com/DAO1/logo_small.jpeg"},
                    }
                },
            },
            "metadata_hash": "a1a0591662255e72aba330746eee9a50815d4580efaf3e60aa687c7ac12d473d",
            "metadata_url": "https://some_storage.some_region.com/DAO1/metadata.json",
        }

        res = self.client.post(
            reverse("core-dao-add-metadata", kwargs={"pk": "DAO1"}),
            post_data,
            content_type="application/json",
            HTTP_SIGNATURE=signature,
        )

        self.assertEqual(res.status_code, HTTP_201_CREATED)
        self.assertDictEqual(res.data, expected_res)

    def test_dao_add_metadata_invalid_image_file(self):
        keypair = Keypair.random()
        cache.set(key=keypair.public_key, value=self.challenge_key, timeout=5)
        signature = base64.b64encode(keypair.sign(data=self.challenge_key.encode())).decode()
        acc = models.Account.objects.create(address=keypair.public_key)
        models.Dao.objects.create(id="DAO1", contract_id="contract1", name="dao1 name", owner=acc)

        post_data = {
            "email": "some@email.com",
            "description_short": "short description",
            "description_long": "long description",
            "logo": base64.b64encode(b"not an image").decode(),
        }
        res = self.client.post(
            reverse("core-dao-add-metadata", kwargs={"pk": "DAO1"}),
            post_data,
            content_type="application/json",
            HTTP_SIGNATURE=signature,
        )

        self.assertEqual(res.status_code, HTTP_400_BAD_REQUEST)
        self.assertDictEqual(
            res.data,
            {
                "logo": [
                    ErrorDetail(
                        string="Invalid image file. Allowed image types are: jpeg, jpg, png, gif.", code="invalid"
                    )
                ]
            },
        )

    def test_dao_add_metadata_logo_too_big(self):
        keypair = Keypair.random()
        cache.set(key=keypair.public_key, value=self.challenge_key, timeout=5)
        signature = base64.b64encode(keypair.sign(data=self.challenge_key.encode())).decode()
        acc = models.Account.objects.create(address=keypair.public_key)
        models.Dao.objects.create(id="DAO1", contract_id="contract1", name="dao1 name", owner=acc)

        with open("core/tests/test_file_5mb.jpeg", "rb") as f:
            post_data = {
                "email": "some@email.com",
                "description_short": "short description",
                "description_long": "long description",
                "logo": base64.b64encode(f.read()).decode(),
            }
        res = self.client.post(
            reverse("core-dao-add-metadata", kwargs={"pk": "DAO1"}),
            post_data,
            content_type="application/json",
            HTTP_SIGNATURE=signature,
        )

        self.assertEqual(res.status_code, HTTP_400_BAD_REQUEST)
        self.assertDictEqual(
            res.data, {"logo": [ErrorDetail(string="The uploaded file is too big. Max size: 2.0 mb.", code="invalid")]}
        )

    def test_dao_add_metadata_403(self):
        with open("core/tests/test_file.jpeg", "rb") as f:
            post_data = {
                "email": "some@email.com",
                "description": "some description",
                "logo": base64.b64encode(f.read()).decode(),
            }

        res = self.client.post(
            reverse("core-dao-add-metadata", kwargs={"pk": "dao1"}),
            post_data,
            content_type="application/json",
            HTTP_SIGNATURE="wrong signature",
        )

        self.assertEqual(res.status_code, HTTP_403_FORBIDDEN)
        self.assertEqual(
            res.data,
            {
                "error": ErrorDetail(
                    code="permission_denied",
                    string="Only the DAO owner has access to this action. "
                    "Header needs to contain signature=*signed-challenge*.",
                )
            },
        )

    def test_asset_get(self):
        expected_res = {"address": "a1", "dao_id": "dao1", "owner_id": "acc1", "total_supply": 1000}

        with self.assertNumQueries(1):
            res = self.client.get(reverse("core-asset-detail", kwargs={"pk": "a1"}))

        self.assertDictEqual(res.data, expected_res)

    def test_asset_get_list(self):
        expected_res = wrap_in_pagination_res(
            [
                {"address": "a1", "dao_id": "dao1", "owner_id": "acc1", "total_supply": 1000},
                {"address": "a2", "dao_id": "dao2", "owner_id": "acc2", "total_supply": 200},
            ]
        )
        with self.assertNumQueries(2):
            res = self.client.get(reverse("core-asset-list"))

        self.assertDictEqual(res.data, expected_res)

    def test_proposal_get(self):
        expected_res = {
            "id": "prop1",
            "dao_id": "dao1",
            "creator_id": "acc1",
            "metadata": {"a": 1},
            "metadata_url": "url1",
            "metadata_hash": "hash1",
            "fault": None,
            "status": models.ProposalStatus.RUNNING,
            "votes": {"pro": 800, "contra": 100, "abstained": 100, "total": 1000},
            "birth_block_number": 10,
            "setup_complete": False,
        }

        with self.assertNumQueries(2):
            res = self.client.get(reverse("core-proposal-detail", kwargs={"pk": "prop1"}))

        self.assertDictEqual(res.data, expected_res)

    def test_proposal_list(self):
        expected_res = wrap_in_pagination_res(
            [
                {
                    "id": "prop1",
                    "dao_id": "dao1",
                    "creator_id": "acc1",
                    "metadata": {"a": 1},
                    "metadata_url": "url1",
                    "metadata_hash": "hash1",
                    "fault": None,
                    "status": models.ProposalStatus.RUNNING,
                    "votes": {"pro": 800, "contra": 100, "abstained": 100, "total": 1000},
                    "birth_block_number": 10,
                    "setup_complete": False,
                },
                {
                    "id": "prop2",
                    "dao_id": "dao2",
                    "creator_id": "acc2",
                    "metadata": {"a": 2},
                    "metadata_url": "url2",
                    "metadata_hash": "hash2",
                    "fault": "some reason",
                    "status": models.ProposalStatus.FAULTED,
                    "votes": {"pro": 0, "contra": 200, "abstained": 0, "total": 200},
                    "birth_block_number": 15,
                    "setup_complete": True,
                },
            ]
        )

        with self.assertNumQueries(3):
            res = self.client.get(reverse("core-proposal-list"))

        self.assertDictEqual(res.data, expected_res)

    def test_proposal_add_metadata(self):
        keypair = Keypair.random()
        signature = base64.b64encode(keypair.sign(data=self.challenge_key.encode())).decode()
        acc = models.Account.objects.create(address=keypair.public_key)
        models.Proposal.objects.create(id="PROP1", dao_id="dao1", creator=acc, birth_block_number=10)
        cache.set(key="acc1", value=self.challenge_key, timeout=5)

        post_data = {
            "title": "some title",
            "description": "short description",
            "url": "https://www.some-url.com/",
        }
        expected_res = {
            "metadata": post_data,
            "metadata_hash": "384f400447f439767311418582fb9f779ba44e18905d225598b48f32eb950ce1",
            "metadata_url": "https://some_storage.some_region.com/dao1/proposals/PROP1/metadata.json",
        }

        with self.assertNumQueries(3):
            res = self.client.post(
                reverse("core-proposal-add-metadata", kwargs={"pk": "PROP1"}),
                post_data,
                content_type="application/json",
                HTTP_SIGNATURE=signature,
            )

        self.assertEqual(res.status_code, HTTP_201_CREATED, res.data)
        self.assertDictEqual(res.data, expected_res)

    def test_proposal_add_metadata_403(self):
        post_data = {
            "title": "some title",
            "description": "short description",
            "url": "https://www.some-url.com/",
        }

        with self.assertNumQueries(3):
            res = self.client.post(
                reverse("core-proposal-add-metadata", kwargs={"pk": "prop1"}),
                post_data,
                content_type="application/json",
                HTTP_SIGNATURE="wrong signature",
            )

        self.assertEqual(res.status_code, HTTP_403_FORBIDDEN)
        self.assertEqual(
            res.data,
            {
                "error": ErrorDetail(
                    code="permission_denied",
                    string="Only the Proposal creator has access to this action. "
                    "Header needs to contain signature=*signed-challenge*.",
                )
            },
        )

    def test_proposal_report_faulted(self):
        cache.clear()
        keypair = Keypair.random()
        cache.set(key="acc1", value=self.challenge_key, timeout=5)
        signature = base64.b64encode(keypair.sign(data=self.challenge_key.encode())).decode()
        acc = models.Account.objects.create(address=keypair.public_key)
        models.AssetHolding.objects.create(owner=acc, asset_id="a1", balance=10)
        proposal_id = "prop1"
        post_data = {"reason": "very good reason"}

        with self.assertNumQueries(4):
            res = self.client.post(
                reverse("core-proposal-report-faulted", kwargs={"pk": proposal_id}),
                post_data,
                content_type="application/json",
                HTTP_SIGNATURE=signature,
            )

        self.assertEqual(res.data, {**post_data, "proposal_id": proposal_id})

    def test_proposal_report_faulted_no_holdings(self):
        cache.clear()
        keypair = Keypair.random()
        cache.set(key="acc1", value=self.challenge_key, timeout=5)
        signature = base64.b64encode(keypair.sign(data=self.challenge_key.encode())).decode()
        models.Account.objects.create(address=keypair.public_key)
        proposal_id = "prop1"
        post_data = {"reason": "very good reason"}

        with self.assertNumQueries(2):
            res = self.client.post(
                reverse("core-proposal-report-faulted", kwargs={"pk": proposal_id}),
                post_data,
                content_type="application/json",
                HTTP_SIGNATURE=signature,
            )

        self.assertEqual(
            res.data,
            {
                "error": ErrorDetail(
                    string="This request's header needs to contain signature=*signed-challenge*.",
                    code="permission_denied",
                )
            },
        )

    def test_proposal_report_faulted_throttle(self):
        cache.clear()
        keypair = Keypair.random()
        cache.set(key="acc1", value=self.challenge_key, timeout=5)
        signature = base64.b64encode(keypair.sign(data=self.challenge_key.encode())).decode()
        acc = models.Account.objects.create(address=keypair.public_key)
        models.AssetHolding.objects.create(owner=acc, asset_id="a1", balance=10)
        proposal_id = "prop1"
        post_data = {"reason": "very good reason", "proposal_id": proposal_id}

        call = partial(
            self.client.post,
            reverse("core-proposal-report-faulted", kwargs={"pk": proposal_id}),
            post_data,
            content_type="application/json",
            HTTP_SIGNATURE=signature,
        )
        for count in range(7):
            if count < 3:
                with self.assertNumQueries(4):
                    res = call()
                self.assertEqual(res.data, post_data)
            elif count < 5:
                with self.assertNumQueries(3):
                    res = call()
                self.assertEqual(res.data, {"detail": "The proposal report maximum has already been reached."})
            else:
                with self.assertNumQueries(2):
                    res = call()
                self.assertEqual(
                    res.data,
                    {
                        "detail": ErrorDetail(
                            "Request was throttled. Expected available in 3600 seconds.", code="throttled"
                        )
                    },
                )

    def test_reports(self):
        models.ProposalReport.objects.create(proposal_id="prop1", reason="reason 1")
        models.ProposalReport.objects.create(proposal_id="prop1", reason="reason 2")
        models.ProposalReport.objects.create(proposal_id="prop2", reason="reason 3")  # should not appear
        expected_res = [
            {"proposal_id": "prop1", "reason": "reason 1"},
            {"proposal_id": "prop1", "reason": "reason 2"},
        ]
        with self.assertNumQueries(1):
            res = self.client.get(reverse("core-proposal-reports", kwargs={"pk": "prop1"}))

        self.assertCountEqual(res.data, expected_res)
