import base64
import secrets
from collections.abc import Collection
from unittest.mock import PropertyMock, patch

from ddt import data, ddt
from django.conf import settings
from django.core.cache import cache
from django.urls import reverse
from rest_framework.exceptions import ErrorDetail
from rest_framework.status import HTTP_201_CREATED, HTTP_400_BAD_REQUEST
from substrateinterface import Keypair

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
    "asset_id": 1,
    "proposal_duration": 10,
    "proposal_token_deposit": 123,
    "minimum_majority_per_1024": 50,
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
    "asset_id": 2,
    "proposal_duration": 15,
    "proposal_token_deposit": 234,
    "minimum_majority_per_1024": 45,
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
            dao_id="dao1", proposal_duration=10, proposal_token_deposit=123, minimum_majority=50
        )
        models.Dao.objects.create(
            id="dao2", contract_id="contract2", name="dao2 name", creator_id="acc2", owner_id="acc2"
        )
        models.Governance.objects.create(
            dao_id="dao2", proposal_duration=15, proposal_token_deposit=234, minimum_majority=45
        )
        models.Asset.objects.create(id=1, owner_id="acc1", dao_id="dao1", total_supply=1000)
        models.Asset.objects.create(id=2, owner_id="acc2", dao_id="dao2", total_supply=200)
        models.AssetHolding.objects.create(asset_id=1, owner_id="acc1", balance=500)
        models.AssetHolding.objects.create(asset_id=1, owner_id="acc2", balance=300)
        models.AssetHolding.objects.create(asset_id=1, owner_id="acc3", balance=100)
        models.AssetHolding.objects.create(asset_id=1, owner_id="acc4", balance=100)
        models.AssetHolding.objects.create(asset_id=2, owner_id="acc2", balance=200)
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
        cache.set(key="current_block", value=(1, "some hash"))

        with self.assertNumQueries(0):
            res = self.client.get(reverse("core-welcome"))

        self.assertEqual(res.headers["Block-Number"], "1")
        self.assertEqual(res.headers["Block-Hash"], "some hash")

    def test_stats(self):
        expected_res = {"account_count": 4, "dao_count": 2, "proposal_count": 2, "vote_count": 4}

        with self.assertNumQueries(4):
            res = self.client.get(reverse("core-stats"))

        self.assertDictEqual(res.data, expected_res)

    def test_config(self):
        expected_res = {
            "deposit_to_create_dao": settings.DEPOSIT_TO_CREATE_DAO,
            "deposit_to_create_proposal": settings.DEPOSIT_TO_CREATE_PROPOSAL,
            "block_creation_interval": settings.BLOCK_CREATION_INTERVAL,
        }

        with self.assertNumQueries(0):
            res = self.client.get(reverse("core-config"))

        self.assertDictEqual(res.data, expected_res)

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
        {"id": "dao2"},
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
            {"order_by": "id"},
            [
                expected_dao1_res,
                expected_dao2_res,
                {
                    "id": "dao3",
                    "contract_id": "contract3",
                    "name": "3",
                    "creator_id": "acc1",
                    "owner_id": "acc2",
                    "asset_id": None,
                    "proposal_duration": None,
                    "proposal_token_deposit": None,
                    "minimum_majority_per_1024": None,
                    "setup_complete": True,
                    "metadata": None,
                    "metadata_url": None,
                    "metadata_hash": None,
                },
            ],
        ),
        (
            {"order_by": "name"},
            [
                {
                    "id": "dao3",
                    "contract_id": "contract3",
                    "name": "3",
                    "creator_id": "acc1",
                    "owner_id": "acc2",
                    "asset_id": None,
                    "proposal_duration": None,
                    "proposal_token_deposit": None,
                    "minimum_majority_per_1024": None,
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
            {"order_by": "owner_id,id"},
            [
                expected_dao1_res,
                expected_dao2_res,
                {
                    "id": "dao3",
                    "contract_id": "contract3",
                    "name": "3",
                    "creator_id": "acc1",
                    "owner_id": "acc2",
                    "asset_id": None,
                    "proposal_duration": None,
                    "proposal_token_deposit": None,
                    "minimum_majority_per_1024": None,
                    "setup_complete": True,
                    "metadata": None,
                    "metadata_url": None,
                    "metadata_hash": None,
                },
            ],
        ),
    )
    def test_dao_list_order_by(self, case):
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
            {"prioritise_owner": "acc2", "order_by": "-name"},
            [
                {
                    "id": "dao4",
                    "contract_id": "contract4",
                    "name": "dao4 name",
                    "creator_id": "acc2",
                    "owner_id": "acc2",
                    "asset_id": 4,
                    "proposal_duration": None,
                    "proposal_token_deposit": None,
                    "minimum_majority_per_1024": None,
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
                    "asset_id": 3,
                    "proposal_duration": None,
                    "proposal_token_deposit": None,
                    "minimum_majority_per_1024": None,
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
            {"prioritise_holder": "acc3", "order_by": "-name"},
            [
                {
                    "id": "dao4",
                    "contract_id": "contract4",
                    "name": "dao4 name",
                    "creator_id": "acc2",
                    "owner_id": "acc2",
                    "asset_id": 4,
                    "proposal_duration": None,
                    "proposal_token_deposit": None,
                    "minimum_majority_per_1024": None,
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
                    "asset_id": 3,
                    "proposal_duration": None,
                    "proposal_token_deposit": None,
                    "minimum_majority_per_1024": None,
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
            {"prioritise_owner": "acc2", "prioritise_holder": "acc3", "order_by": "name"},
            [
                expected_dao2_res,
                {
                    "id": "dao4",
                    "contract_id": "contract4",
                    "name": "dao4 name",
                    "creator_id": "acc2",
                    "owner_id": "acc2",
                    "asset_id": 4,
                    "proposal_duration": None,
                    "proposal_token_deposit": None,
                    "minimum_majority_per_1024": None,
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
                    "asset_id": 3,
                    "proposal_duration": None,
                    "proposal_token_deposit": None,
                    "minimum_majority_per_1024": None,
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
        models.Asset.objects.create(id=3, owner_id="acc1", dao_id="dao3", total_supply=100)
        models.Asset.objects.create(id=4, owner_id="acc2", dao_id="dao4", total_supply=200)
        models.AssetHolding.objects.create(asset_id=3, owner_id="acc3", balance=100)
        models.AssetHolding.objects.create(asset_id=4, owner_id="acc3", balance=200)

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
        keypair = Keypair.create_from_mnemonic(Keypair.generate_mnemonic())
        cache.set(key=keypair.ss58_address, value=self.challenge_key, timeout=5)
        signature = base64.b64encode(keypair.sign(data=self.challenge_key)).decode()
        acc = models.Account.objects.create(address=keypair.ss58_address)
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
        keypair = Keypair.create_from_mnemonic(Keypair.generate_mnemonic())
        cache.set(key=keypair.ss58_address, value=self.challenge_key, timeout=5)
        signature = base64.b64encode(keypair.sign(data=self.challenge_key)).decode()
        acc = models.Account.objects.create(address=keypair.ss58_address)
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
        keypair = Keypair.create_from_mnemonic(Keypair.generate_mnemonic())
        cache.set(key=keypair.ss58_address, value=self.challenge_key, timeout=5)
        signature = base64.b64encode(keypair.sign(data=self.challenge_key)).decode()
        acc = models.Account.objects.create(address=keypair.ss58_address)
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

    # todo
    # def test_dao_add_metadata_403(self):
    #     with open("core/tests/test_file.jpeg", "rb") as f:
    #         post_data = {
    #             "email": "some@email.com",
    #             "description": "some description",
    #             "logo": base64.b64encode(f.read()).decode(),
    #         }
    #
    #     res = self.client.post(
    #         reverse("core-dao-add-metadata", kwargs={"pk": "dao1"}),
    #         post_data,
    #         content_type="application/json",
    #         HTTP_SIGNATURE="wrong signature",
    #     )
    #
    #     self.assertEqual(res.status_code, HTTP_403_FORBIDDEN)
    #     self.assertEqual(
    #         res.data,
    #         {
    #             "error": ErrorDetail(
    #                 code="permission_denied",
    #                 string="Only the DAO owner has access to this action. "
    #                 "Header needs to contain signature=*signed-challenge*.",
    #             )
    #         },
    #     )

    def test_asset_get(self):
        expected_res = {"id": 1, "dao_id": "dao1", "owner_id": "acc1", "total_supply": 1000}

        with self.assertNumQueries(1):
            res = self.client.get(reverse("core-asset-detail", kwargs={"pk": 1}))

        self.assertDictEqual(res.data, expected_res)

    def test_asset_get_list(self):
        expected_res = wrap_in_pagination_res(
            [
                {"id": 1, "dao_id": "dao1", "owner_id": "acc1", "total_supply": 1000},
                {"id": 2, "dao_id": "dao2", "owner_id": "acc2", "total_supply": 200},
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
                },
            ]
        )

        with self.assertNumQueries(3):
            res = self.client.get(reverse("core-proposal-list"))

        self.assertDictEqual(res.data, expected_res)

    # todo
    # def test_proposal_add_metadata(self):
    #     keypair = Keypair.create_from_mnemonic(Keypair.generate_mnemonic())
    #     signature = base64.b64encode(keypair.sign(data=self.challenge_key)).decode()
    #     acc = models.Account.objects.create(address=keypair.ss58_address)
    #     models.Proposal.objects.create(id="PROP1", dao_id="dao1", creator=acc, birth_block_number=10)
    #     cache.set(key="acc1", value=self.challenge_key, timeout=5)
    #
    #     post_data = {
    #         "title": "some title",
    #         "description": "short description",
    #         "url": "https://www.some-url.com/",
    #     }
    #     expected_res = {
    #         "metadata": post_data,
    #         "metadata_hash": "384f400447f439767311418582fb9f779ba44e18905d225598b48f32eb950ce1",
    #         "metadata_url": "https://some_storage.some_region.com/dao1/proposals/PROP1/metadata.json",
    #     }
    #
    #     with self.assertNumQueries(4):
    #         res = self.client.post(
    #             reverse("core-proposal-add-metadata", kwargs={"pk": "PROP1"}),
    #             post_data,
    #             content_type="application/json",
    #             HTTP_SIGNATURE=signature,
    #         )
    #
    #     self.assertEqual(res.status_code, HTTP_201_CREATED, res.data)
    #     self.assertDictEqual(res.data, expected_res)

    # todo
    # def test_proposal_add_metadata_403(self):
    #     post_data = {
    #         "title": "some title",
    #         "description": "short description",
    #         "url": "https://www.some-url.com/",
    #     }
    #
    #     with self.assertNumQueries(3):
    #         res = self.client.post(
    #             reverse("core-proposal-add-metadata", kwargs={"pk": "prop1"}),
    #             post_data,
    #             content_type="application/json",
    #             HTTP_SIGNATURE="wrong signature",
    #         )
    #
    #     self.assertEqual(res.status_code, HTTP_403_FORBIDDEN)
    #     self.assertEqual(
    #         res.data,
    #         {
    #             "error": ErrorDetail(
    #                 code="permission_denied",
    #                 string="Only the Proposal creator has access to this action. "
    #                 "Header needs to contain signature=*signed-challenge*.",
    #             )
    #         },
    #     )

    # todo
    # def test_proposal_report_faulted(self):
    #     cache.clear()
    #     keypair = Keypair.create_from_mnemonic(Keypair.generate_mnemonic())
    #     cache.set(key="acc1", value=self.challenge_key, timeout=5)
    #     signature = base64.b64encode(keypair.sign(data=self.challenge_key)).decode()
    #     acc = models.Account.objects.create(address=keypair.ss58_address)
    #     models.AssetHolding.objects.create(owner=acc, asset_id=1, balance=10)
    #     proposal_id = "prop1"
    #     post_data = {"reason": "very good reason"}
    #
    #     with self.assertNumQueries(4):
    #         res = self.client.post(
    #             reverse("core-proposal-report-faulted", kwargs={"pk": proposal_id}),
    #             post_data,
    #             content_type="application/json",
    #             HTTP_SIGNATURE=signature,
    #         )
    #
    #     self.assertEqual(res.data, {**post_data, "proposal_id": proposal_id})

    # todo
    # def test_proposal_report_faulted_no_holdings(self):
    #     cache.clear()
    #     keypair = Keypair.create_from_mnemonic(Keypair.generate_mnemonic())
    #     cache.set(key="acc1", value=self.challenge_key, timeout=5)
    #     signature = base64.b64encode(keypair.sign(data=self.challenge_key)).decode()
    #     models.Account.objects.create(address=keypair.ss58_address)
    #     proposal_id = "prop1"
    #     post_data = {"reason": "very good reason"}
    #
    #     with self.assertNumQueries(2):
    #         res = self.client.post(
    #             reverse("core-proposal-report-faulted", kwargs={"pk": proposal_id}),
    #             post_data,
    #             content_type="application/json",
    #             HTTP_SIGNATURE=signature,
    #         )
    #
    #     self.assertEqual(
    #         res.data,
    #         {
    #             "error": ErrorDetail(
    #                 string="This request's header needs to contain signature=*signed-challenge*.",
    #                 code="permission_denied",
    #             )
    #         },
    #     )

    # todo
    # def test_proposal_report_faulted_throttle(self):
    #     cache.clear()
    #     keypair = Keypair.create_from_mnemonic(Keypair.generate_mnemonic())
    #     cache.set(key="acc1", value=self.challenge_key, timeout=5)
    #     signature = base64.b64encode(keypair.sign(data=self.challenge_key)).decode()
    #     acc = models.Account.objects.create(address=keypair.ss58_address)
    #     models.AssetHolding.objects.create(owner=acc, asset_id=1, balance=10)
    #     proposal_id = "prop1"
    #     post_data = {"reason": "very good reason", "proposal_id": proposal_id}
    #
    #     call = partial(
    #         self.client.post,
    #         reverse("core-proposal-report-faulted", kwargs={"pk": proposal_id}),
    #         post_data,
    #         content_type="application/json",
    #         HTTP_SIGNATURE=signature,
    #     )
    #     for count in range(7):
    #         if count < 3:
    #             with self.assertNumQueries(4):
    #                 res = call()
    #             self.assertEqual(res.data, post_data)
    #         elif count < 5:
    #             with self.assertNumQueries(3):
    #                 res = call()
    #             self.assertEqual(res.data, {"detail": "The proposal report maximum has already been reached."})
    #         else:
    #             with self.assertNumQueries(2):
    #                 res = call()
    #             self.assertEqual(
    #                 res.data,
    #                 {
    #                     "detail": ErrorDetail(
    #                         "Request was throttled. Expected available in 3600 seconds.", code="throttled"
    #                     )
    #                 },
    #             )

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
