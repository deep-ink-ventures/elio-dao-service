import json
import random
from io import BytesIO
from unittest.mock import call, patch

from ddt import data, ddt
from django.core.cache import cache
from django.db import IntegrityError

from core import models
from core.event_handler import (
    ParseBlockException,
    SorobanEventHandler,
    soroban_event_handler,
)
from core.file_handling.file_handler import file_handler
from core.tests.testcases import IntegrationTestCase


@ddt
class EventHandlerTest(IntegrationTestCase):
    def setUp(self):
        self.contr1 = models.Contract.objects.create(id="contract1")
        self.contr2 = models.Contract.objects.create(id="contract2")
        self.contr3 = models.Contract.objects.create(id="contract3")
        self.acc1 = models.Account.objects.create(address="acc1")
        self.acc2 = models.Account.objects.create(address="acc2")
        self.dao1 = models.Dao.objects.create(
            id="dao1", contract_id="contract1", name="dao1 name", owner_id="acc1", creator_id="acc1"
        )
        self.dao2 = models.Dao.objects.create(
            id="dao2", contract_id="contract2", name="dao2 name", owner_id="acc2", creator_id="acc2"
        )

    def test__create_daos(self):
        models.Contract.objects.create(id="contract4")
        event_data = {
            "contract3": [
                {"owner_id": "acc2", "dao_id": "dao3", "dao_name": "dao3 name", "not": "interesting"},
            ],
            "contract4": [
                {"owner_id": "acc3", "dao_id": "dao4", "dao_name": "dao4 name", "not": "interesting"},
            ],
        }
        expected_accs = [self.acc1, self.acc2, models.Account(address="acc3")]
        expected_daos = [
            self.dao1,
            self.dao2,
            models.Dao(id="dao3", contract_id="contract3", name="dao3 name", owner_id="acc2", creator_id="acc2"),
            models.Dao(id="dao4", contract_id="contract4", name="dao4 name", owner_id="acc3", creator_id="acc3"),
        ]

        with self.assertNumQueries(2):
            soroban_event_handler._create_daos(event_data=event_data)

        self.assertModelsEqual(models.Account.objects.order_by("address"), expected_accs)
        self.assertModelsEqual(models.Dao.objects.order_by("id"), expected_daos)

    def test__delete_daos(self):
        models.Dao.objects.create(id="dao3", contract_id="contract3", name="dao3 name", owner_id="acc1")
        event_data = {
            "contract1": [
                {"dao_id": "dao1", "not": "interesting"},
            ],
            "contract2": [
                {"dao_id": "dao2", "not": "interesting"},
            ],
        }
        expected_daos = [
            models.Dao(id="dao3", contract_id="contract3", name="dao3 name", owner_id="acc1"),
        ]

        with self.assertNumQueries(5):
            soroban_event_handler._delete_daos(event_data=event_data)

        self.assertModelsEqual(models.Dao.objects.all(), expected_daos)

    def test__transfer_dao_ownerships(self):
        models.Account.objects.create(address="acc3")
        models.Dao.objects.create(
            id="dao3",
            contract_id="contract3",
            name="dao3 name",
            owner_id="acc3",
            creator_id="acc3",
            setup_complete=True,
        ),
        event_data = {
            "contract1": [
                {"dao_id": "dao1", "new_owner_id": "acc3", "not": "interesting"},
            ],
            "contract2": [
                {"dao_id": "dao2", "new_owner_id": "acc1", "not": "interesting"},
            ],
            "contract3": [
                {"dao_id": "dao3", "new_owner_id": "acc4", "not": "interesting"},
            ],
        }
        expected_accounts = [self.acc1, self.acc2, models.Account(address="acc3"), models.Account(address="acc4")]
        expected_daos = [
            models.Dao(
                id="dao1",
                contract_id="contract1",
                name="dao1 name",
                owner_id="acc3",
                creator_id="acc1",
                setup_complete=True,
            ),
            models.Dao(
                id="dao2",
                contract_id="contract2",
                name="dao2 name",
                owner_id="acc1",
                creator_id="acc2",
                setup_complete=True,
            ),
            models.Dao(
                id="dao3",
                contract_id="contract3",
                name="dao3 name",
                owner_id="acc4",
                creator_id="acc3",
                setup_complete=True,
            ),
        ]
        with self.assertNumQueries(3):
            soroban_event_handler._transfer_dao_ownerships(event_data=event_data)

        self.assertModelsEqual(models.Dao.objects.order_by("id"), expected_daos)
        self.assertModelsEqual(models.Account.objects.order_by("address"), expected_accounts)

    def test__create_assets(self):
        event_data = {
            "contract1": [
                {
                    "dao_id": "dao1",
                    "owner_id": "acc1",
                    "asset_id": "CAN4KOP4PLNTZR7G4USOFBI65GGWJCVCBT7TLIO4EYKVNPDWA554IOV5",
                    "governance_id": "g1",
                    "not": "interesting",
                },
            ],
            "contract2": [
                {
                    "dao_id": "dao2",
                    "owner_id": "acc2",
                    "asset_id": "CB57XWMJXNLZSHBLLM2LHBU4DNUUA64KOTUBXMI5TYD2LMXSJ7FLRIXD",
                    "governance_id": "g1",
                    "not": "interesting",
                },
            ],
        }
        expected_assets = [
            models.Asset(
                id="1bc539fc7adb3cc7e6e524e2851ee98d648aa20cff35a1dc261556bc76077bc4",
                address="CAN4KOP4PLNTZR7G4USOFBI65GGWJCVCBT7TLIO4EYKVNPDWA554IOV5",
                total_supply=0,
                owner_id="acc1",
                dao_id="dao1",
            ),
            models.Asset(
                id="7bfbd989bb57991c2b5b34b3869c1b69407b8a74e81bb11d9e07a5b2f24fcab8",
                address="CB57XWMJXNLZSHBLLM2LHBU4DNUUA64KOTUBXMI5TYD2LMXSJ7FLRIXD",
                total_supply=0,
                owner_id="acc2",
                dao_id="dao2",
            ),
        ]
        expected_asset_holdings = [
            models.AssetHolding(
                asset_id="1bc539fc7adb3cc7e6e524e2851ee98d648aa20cff35a1dc261556bc76077bc4", owner_id="acc1", balance=0
            ),
            models.AssetHolding(
                asset_id="7bfbd989bb57991c2b5b34b3869c1b69407b8a74e81bb11d9e07a5b2f24fcab8", owner_id="acc2", balance=0
            ),
        ]

        with self.assertNumQueries(3):
            soroban_event_handler._create_assets(event_data=event_data)

        self.assertModelsEqual(models.Asset.objects.all(), expected_assets)
        self.assertModelsEqual(
            models.AssetHolding.objects.all(), expected_asset_holdings, ignore_fields=("id", "created_at", "updated_at")
        )

    def test__mint_tokens(self):
        models.Account.objects.create(address="acc3")
        models.Dao.objects.create(id="dao3", contract_id="contract3", name="dao3 name", owner_id="acc3")
        models.Asset.objects.create(id="1", total_supply=0, owner_id="acc1", dao_id="dao1")
        models.Asset.objects.create(id="2", total_supply=0, owner_id="acc2", dao_id="dao2")
        models.Asset.objects.create(id="3", total_supply=0, owner_id="acc3", dao_id="dao3")
        models.AssetHolding.objects.create(asset_id=1, owner_id="acc1", balance=0)
        models.AssetHolding.objects.create(asset_id=2, owner_id="acc2", balance=0)
        models.AssetHolding.objects.create(asset_id=3, owner_id="acc3", balance=0)
        event_data = {
            "1": [{"owner_id": "acc1", "amount": 123}],
            "2": [{"owner_id": "acc2", "amount": 234}],
        }
        expected_assets = [
            models.Asset(id="1", total_supply=123, owner_id="acc1", dao_id="dao1"),
            models.Asset(id="2", total_supply=234, owner_id="acc2", dao_id="dao2"),
            models.Asset(id="3", total_supply=0, owner_id="acc3", dao_id="dao3"),
        ]
        expected_asset_holdings = [
            models.AssetHolding(asset_id="1", owner_id="acc1", balance=123),
            models.AssetHolding(asset_id="2", owner_id="acc2", balance=234),
            models.AssetHolding(asset_id="3", owner_id="acc3", balance=0),
        ]

        with self.assertNumQueries(4):
            soroban_event_handler._mint_tokens(event_data=event_data)

        self.assertModelsEqual(
            models.Asset.objects.order_by("id").all(), expected_assets, ignore_fields=["created_at", "updated_at"]
        )
        self.assertModelsEqual(
            models.AssetHolding.objects.order_by("asset_id").all(),
            expected_asset_holdings,
            ignore_fields=["id", "created_at", "updated_at"],
        )

    def test__transfer_assets(self):
        models.Account.objects.create(address="acc3")
        self.contr3 = models.Contract.objects.create(id="contract4")
        models.Dao.objects.create(id="dao3", contract_id="contract3", name="dao3 name", owner_id="acc3")
        models.Dao.objects.create(id="dao4", contract_id="contract4", name="dao4 name", owner_id="acc3")
        models.Asset.objects.create(id="1", total_supply=150, owner_id="acc1", dao_id="dao1")
        models.Asset.objects.create(id="2", total_supply=250, owner_id="acc2", dao_id="dao2")
        models.Asset.objects.create(id="3", total_supply=300, owner_id="acc3", dao_id="dao3")
        models.Asset.objects.create(id="4", total_supply=400, owner_id="acc3", dao_id="dao4")
        models.AssetHolding.objects.create(asset_id="1", owner_id="acc1", balance=100)
        models.AssetHolding.objects.create(asset_id="1", owner_id="acc3", balance=50)
        models.AssetHolding.objects.create(asset_id="2", owner_id="acc2", balance=200)
        models.AssetHolding.objects.create(asset_id="2", owner_id="acc3", balance=50)
        models.AssetHolding.objects.create(asset_id="3", owner_id="acc2", balance=50)
        models.AssetHolding.objects.create(asset_id="3", owner_id="acc3", balance=300)
        models.AssetHolding.objects.create(asset_id="4", owner_id="acc3", balance=400)
        transfers = [
            {"amount": 10, "owner_id": "acc1", "new_owner_id": "acc2", "not": "interesting"},
            {"amount": 15, "owner_id": "acc1", "new_owner_id": "acc2", "not": "interesting"},
            {"amount": 25, "owner_id": "acc3", "new_owner_id": "acc2", "not": "interesting"},
        ]
        # order mustn't matter
        random.shuffle(transfers)
        event_data = {
            "1": transfers,
            "2": [{"amount": 20, "owner_id": "acc2", "new_owner_id": "acc1", "not": "interesting"}],
            "3": [{"amount": 50, "owner_id": "acc3", "new_owner_id": "acc2", "not": "interesting"}],
        }
        expected_asset_holdings = [
            models.AssetHolding(asset_id="1", owner_id="acc1", balance=75),  # 100 - 10 - 15
            models.AssetHolding(asset_id="1", owner_id="acc2", balance=50),  # 0 + 10 + 15 + 25
            models.AssetHolding(asset_id="1", owner_id="acc3", balance=25),  # 50 - 25
            models.AssetHolding(asset_id="2", owner_id="acc1", balance=20),  # 0 + 20
            models.AssetHolding(asset_id="2", owner_id="acc2", balance=180),  # 200 - 20
            models.AssetHolding(asset_id="2", owner_id="acc3", balance=50),  # 50
            models.AssetHolding(asset_id="3", owner_id="acc2", balance=100),  # 50 + 50
            models.AssetHolding(asset_id="3", owner_id="acc3", balance=250),  # 300 - 50
            models.AssetHolding(asset_id="4", owner_id="acc3", balance=400),  # 300
        ]
        expected_daos = [
            models.Dao(
                id="dao1",
                contract_id="contract1",
                name="dao1 name",
                owner_id="acc1",
                creator_id="acc1",
                setup_complete=True,
            ),
            models.Dao(
                id="dao2",
                contract_id="contract2",
                name="dao2 name",
                owner_id="acc2",
                creator_id="acc2",
                setup_complete=True,
            ),
            models.Dao(id="dao3", contract_id="contract3", name="dao3 name", owner_id="acc3", setup_complete=True),
            models.Dao(id="dao4", contract_id="contract4", name="dao4 name", owner_id="acc3", setup_complete=False),
        ]

        with self.assertNumQueries(5):
            soroban_event_handler._transfer_assets(event_data=event_data)

        self.assertModelsEqual(
            models.AssetHolding.objects.order_by("asset_id", "owner_id"),
            expected_asset_holdings,
            ignore_fields=("id", "created_at", "updated_at"),
        )
        self.assertModelsEqual(models.Dao.objects.order_by("id"), expected_daos)

    @patch("core.file_handling.file_handler.urlopen")
    def test__set_dao_metadata(self, urlopen_mock):
        models.Account.objects.create(address="acc3")
        models.Dao.objects.create(
            id="dao3", contract_id="contract3", name="dao3 name", owner_id="acc3", creator_id="acc3"
        )
        metadata_1 = {"a": 1}
        file_1 = BytesIO(json.dumps(metadata_1).encode())
        metadata_hash_1 = file_handler._hash(file_1.getvalue())
        metadata_2 = {"a": 2}
        file_2 = BytesIO(json.dumps(metadata_2).encode())
        metadata_hash_2 = file_handler._hash(file_2.getvalue())
        urlopen_mock.side_effect = lambda url: {"url1": file_1, "url2": file_2}.get(url)
        event_data = {
            "contract1": [{"dao_id": "dao1", "url": "url1", "hash": metadata_hash_1, "not": "interesting"}],
            "contract2": [{"dao_id": "dao2", "url": "url2", "hash": metadata_hash_2, "not": "interesting"}],
        }
        expected_daos = [
            models.Dao(
                id="dao1",
                contract_id="contract1",
                name="dao1 name",
                owner_id="acc1",
                creator_id="acc1",
                metadata_hash=metadata_hash_1,
                metadata_url="url1",
                metadata=metadata_1,
            ),
            models.Dao(
                id="dao2",
                contract_id="contract2",
                name="dao2 name",
                owner_id="acc2",
                creator_id="acc2",
                metadata_hash=metadata_hash_2,
                metadata_url="url2",
                metadata=metadata_2,
            ),
            models.Dao(
                id="dao3",
                contract_id="contract3",
                name="dao3 name",
                owner_id="acc3",
                creator_id="acc3",
                metadata_hash=None,
                metadata_url=None,
            ),
        ]

        with self.assertNumQueries(2):
            soroban_event_handler._set_dao_metadata(event_data=event_data)

        urlopen_mock.assert_has_calls([call("url1"), call("url2")], any_order=True)
        self.assertModelsEqual(models.Dao.objects.order_by("id"), expected_daos)

    @patch("core.file_handling.file_handler.urlopen")
    @patch("core.tasks.slack_logger")
    def test__set_dao_metadata_hash_mismatch(self, logger_mock, urlopen_mock):
        models.Account.objects.create(address="acc3")
        models.Dao.objects.create(
            id="dao3", contract_id="contract3", name="dao3 name", owner_id="acc3", creator_id="acc3"
        )
        metadata_1 = {"a": 1}
        file_1 = BytesIO(json.dumps(metadata_1).encode())
        metadata_hash_1 = file_handler._hash(file_1.getvalue())
        metadata_2 = {"a": 2}
        file_2 = BytesIO(json.dumps(metadata_2).encode())
        urlopen_mock.side_effect = lambda url: {"url1": file_1, "url2": file_2}.get(url)
        event_data = {
            "contract1": [{"dao_id": "dao1", "url": "url1", "hash": metadata_hash_1, "not": "interesting"}],
            "contract2": [{"dao_id": "dao2", "url": "url2", "hash": "wrong hash", "not": "interesting"}],
        }
        expected_daos = [
            models.Dao(
                id="dao1",
                name="dao1 name",
                contract_id="contract1",
                owner_id="acc1",
                creator_id="acc1",
                metadata_url="url1",
                metadata_hash=metadata_hash_1,
                metadata=metadata_1,
            ),
            models.Dao(
                id="dao2",
                name="dao2 name",
                contract_id="contract2",
                owner_id="acc2",
                creator_id="acc2",
                metadata_url="url2",
                metadata_hash="wrong hash",
            ),
            models.Dao(id="dao3", name="dao3 name", contract_id="contract3", owner_id="acc3", creator_id="acc3"),
        ]

        with self.assertNumQueries(2):
            soroban_event_handler._set_dao_metadata(event_data=event_data)

        urlopen_mock.assert_has_calls([call("url1"), call("url2")], any_order=True)
        logger_mock.error.assert_called_once_with("Hash mismatch while fetching DAO metadata from provided url.")
        self.assertModelsEqual(models.Dao.objects.order_by("id"), expected_daos)

    @patch("core.file_handling.file_handler.FileHandler.download_metadata")
    @patch("core.tasks.slack_logger")
    def test__set_dao_metadata_exception(self, logger_mock, download_metadata_mock):
        models.Account.objects.create(address="acc3")
        models.Dao.objects.create(
            id="dao3", contract_id="contract3", name="dao3 name", owner_id="acc3", creator_id="acc3"
        )
        metadata_1 = {"a": 1}
        file_1 = BytesIO(json.dumps(metadata_1).encode())
        metadata_hash_1 = file_handler._hash(file_1.getvalue())
        metadata_2 = {"a": 2}
        file_2 = BytesIO(json.dumps(metadata_2).encode())
        metadata_hash_2 = file_handler._hash(file_2.getvalue())

        def download_metadata(url, **_):
            if url == "url1":
                raise Exception("roar")
            return metadata_2

        download_metadata_mock.side_effect = download_metadata
        event_data = {
            "contract1": [{"dao_id": "dao1", "url": "url1", "hash": metadata_hash_1, "not": "interesting"}],
            "contract2": [{"dao_id": "dao2", "url": "url2", "hash": metadata_hash_2, "not": "interesting"}],
        }
        expected_daos = [
            models.Dao(
                id="dao1",
                name="dao1 name",
                contract_id="contract1",
                owner_id="acc1",
                creator_id="acc1",
                metadata_url="url1",
                metadata_hash=metadata_hash_1,
                metadata=None,
            ),
            models.Dao(
                id="dao2",
                name="dao2 name",
                contract_id="contract2",
                owner_id="acc2",
                creator_id="acc2",
                metadata_url="url2",
                metadata_hash=metadata_hash_2,
                metadata=metadata_2,
            ),
            models.Dao(id="dao3", name="dao3 name", contract_id="contract3", owner_id="acc3", creator_id="acc3"),
        ]
        with self.assertNumQueries(2):
            soroban_event_handler._set_dao_metadata(event_data=event_data)

        download_metadata_mock.assert_has_calls(
            [
                call(url="url1", metadata_hash=metadata_hash_1),
                call(url="url2", metadata_hash=metadata_hash_2),
            ],
            any_order=True,
        )
        logger_mock.exception.assert_called_once_with("Unexpected error while fetching DAO metadata from provided url.")
        self.assertModelsEqual(models.Dao.objects.order_by("id"), expected_daos)

    @patch("core.file_handling.file_handler.urlopen")
    def test__set_dao_metadata_nothing_to_update(self, urlopen_mock):
        models.Account.objects.create(address="acc3")
        models.Contract.objects.create(id="contract4")
        models.Dao.objects.create(
            id="dao3",
            contract_id="contract3",
            name="dao1 name",
            owner_id="acc1",
            metadata_hash="hash1",
            metadata_url="url1",
        )
        models.Dao.objects.create(
            id="dao4",
            contract_id="contract4",
            name="dao2 name",
            owner_id="acc2",
            metadata_hash="hash2",
            metadata_url="url3",
        )

        event_data = {
            "contract3": [{"dao_id": "dao3", "url": "url1", "hash": "hash1", "not": "interesting"}],
            "contract4": [{"dao_id": "dao4", "url": "url2", "hash": "hash2", "not": "interesting"}],
        }
        expected_daos = [
            self.dao1,
            self.dao2,
            models.Dao(
                id="dao3",
                contract_id="contract3",
                name="dao1 name",
                owner_id="acc1",
                metadata_hash="hash1",
                metadata_url="url1",
            ),
            models.Dao(
                id="dao4",
                contract_id="contract4",
                name="dao2 name",
                owner_id="acc2",
                metadata_hash="hash2",
                metadata_url="url3",
            ),
        ]

        with self.assertNumQueries(1):
            soroban_event_handler._set_dao_metadata(event_data=event_data)

        urlopen_mock.assert_not_called()
        self.assertModelsEqual(models.Dao.objects.order_by("id"), expected_daos)

    def test__dao_set_governance(self):
        models.Account.objects.create(address="acc3")
        models.Dao.objects.create(id="dao3", contract_id="contract3", name="dao3 name", owner_id="acc3")

        event_data = {
            "c1": [
                {
                    "dao_id": "dao1",
                    "proposal_duration": 1,
                    "min_threshold_configuration": 2,
                },
                {
                    "dao_id": "dao2",
                    "proposal_duration": 4,
                    "proposal_token_deposit": 5,
                    "proposal_voting_type": ["MAJORITY"],
                    "min_threshold_configuration": 6,
                },
            ]
        }
        expected_governances = [
            models.Governance(
                dao_id="dao1",
                proposal_duration=1,
                proposal_token_deposit=None,
                type=None,
                min_threshold_configuration=2,
            ),
            models.Governance(
                dao_id="dao2",
                proposal_duration=4,
                proposal_token_deposit=5,
                type=models.GovernanceType.MAJORITY_VOTE,
                min_threshold_configuration=6,
            ),
        ]

        with self.assertNumQueries(2):
            soroban_event_handler._dao_set_governances(event_data=event_data)

        created_governances = models.Governance.objects.order_by("dao_id")
        self.assertModelsEqual(
            created_governances, expected_governances, ignore_fields=["id", "created_at", "updated_at"]
        )
        expected_daos = [
            models.Dao(
                id="dao1",
                contract_id="contract1",
                creator_id="acc1",
                name="dao1 name",
                owner_id="acc1",
                governance=created_governances[0],
            ),
            models.Dao(
                id="dao2",
                contract_id="contract2",
                creator_id="acc2",
                name="dao2 name",
                owner_id="acc2",
                governance=created_governances[1],
            ),
            models.Dao(id="dao3", contract_id="contract3", name="dao3 name", owner_id="acc3", governance=None),
        ]
        self.assertModelsEqual(models.Dao.objects.order_by("id"), expected_daos)

    def test__create_proposals(self):
        models.Account.objects.create(address="acc3")
        models.Dao.objects.create(id="dao3", contract_id="contract3", name="dao3 name", owner_id="acc3")
        models.Asset.objects.create(id=1, dao_id="dao1", owner_id="acc1", total_supply=100)
        models.AssetHolding.objects.create(asset_id=1, owner_id="acc1", balance=50)
        models.AssetHolding.objects.create(asset_id=1, owner_id="acc2", balance=30)
        models.AssetHolding.objects.create(asset_id=1, owner_id="acc3", balance=20)
        models.Asset.objects.create(id=2, dao_id="dao2", owner_id="acc2", total_supply=100)
        models.AssetHolding.objects.create(asset_id=2, owner_id="acc3", balance=50)
        models.AssetHolding.objects.create(asset_id=2, owner_id="acc2", balance=30)
        models.AssetHolding.objects.create(asset_id=2, owner_id="acc1", balance=20)
        models.Asset.objects.create(id=3, dao_id="dao3", owner_id="acc3", total_supply=100)
        models.AssetHolding.objects.create(asset_id=3, owner_id="acc2", balance=50)
        models.AssetHolding.objects.create(asset_id=3, owner_id="acc3", balance=30)
        models.AssetHolding.objects.create(asset_id=3, owner_id="acc1", balance=20)
        event_data = {
            "1": [{"proposal_id": "prop1", "dao_id": "dao1", "owner_id": "acc1"}],
            "2": [{"proposal_id": "prop2", "dao_id": "dao2", "owner_id": "acc2"}],
        }
        expected_proposals = [
            models.Proposal(id="prop1", dao_id="dao1", creator_id="acc1", birth_block_number=123),
            models.Proposal(id="prop2", dao_id="dao2", creator_id="acc2", birth_block_number=123),
        ]
        expected_votes = [
            models.Vote(proposal_id="prop1", voter_id="acc1", voting_power=50, in_favor=None),
            models.Vote(proposal_id="prop1", voter_id="acc2", voting_power=30, in_favor=None),
            models.Vote(proposal_id="prop1", voter_id="acc3", voting_power=20, in_favor=None),
            models.Vote(proposal_id="prop2", voter_id="acc3", voting_power=50, in_favor=None),
            models.Vote(proposal_id="prop2", voter_id="acc2", voting_power=30, in_favor=None),
            models.Vote(proposal_id="prop2", voter_id="acc1", voting_power=20, in_favor=None),
        ]

        with self.assertNumQueries(4):
            soroban_event_handler._create_proposals(
                event_data=event_data, block=models.Block.objects.create(number=123)
            )

        self.assertModelsEqual(models.Proposal.objects.order_by("id"), expected_proposals)
        self.assertModelsEqual(
            models.Vote.objects.order_by("proposal_id", "-voting_power"),
            expected_votes,
            ignore_fields=("created_at", "updated_at", "id"),
        )

    @patch("core.file_handling.file_handler.urlopen")
    def test__set_proposal_metadata(self, urlopen_mock):
        models.Proposal.objects.create(id="1", dao_id="dao1", birth_block_number=10)
        models.Proposal.objects.create(id="2", dao_id="dao2", birth_block_number=10)
        metadata_1 = {"a": 1}
        file_1 = BytesIO(json.dumps(metadata_1).encode())
        metadata_hash_1 = file_handler._hash(file_1.getvalue())
        metadata_2 = {"a": 2}
        file_2 = BytesIO(json.dumps(metadata_2).encode())
        metadata_hash_2 = file_handler._hash(file_2.getvalue())

        urlopen_mock.side_effect = lambda url: {"url1": file_1, "url2": file_2}.get(url)
        event_data = {
            "1": [
                {"proposal_id": "1", "url": "url1", "hash": metadata_hash_1},
            ],
            "2": [
                {"proposal_id": "2", "url": "url2", "hash": metadata_hash_2},
            ],
        }
        expected_proposals = [
            models.Proposal(
                id="1",
                dao_id="dao1",
                metadata_url="url1",
                metadata_hash=metadata_hash_1,
                metadata=metadata_1,
                birth_block_number=10,
                setup_complete=True,
            ),
            models.Proposal(
                id="2",
                dao_id="dao2",
                metadata_url="url2",
                metadata_hash=metadata_hash_2,
                metadata=metadata_2,
                birth_block_number=10,
                setup_complete=True,
            ),
        ]
        with self.assertNumQueries(4):
            soroban_event_handler._set_proposal_metadata(event_data=event_data)

        urlopen_mock.assert_has_calls([call("url1"), call("url2")], any_order=True)
        self.assertModelsEqual(models.Proposal.objects.order_by("id"), expected_proposals)

    @patch("core.tasks.slack_logger")
    @patch("core.file_handling.file_handler.urlopen")
    def test__proposal_set_metadata_hash_mismatch(self, urlopen_mock, logger_mock):
        models.Account.objects.create(address="acc3")
        models.Dao.objects.create(id="dao3", contract_id="contract3", name="dao3 name", owner_id="acc3")
        models.Proposal.objects.create(id="1", dao_id="dao1", birth_block_number=10)
        models.Proposal.objects.create(id="2", dao_id="dao2", birth_block_number=10)
        models.Proposal.objects.create(id="3", dao_id="dao3", birth_block_number=10)
        metadata_1 = {"a": 1}
        file_1 = BytesIO(json.dumps(metadata_1).encode())
        metadata_2 = {"a": 2}
        file_2 = BytesIO(json.dumps(metadata_2).encode())
        metadata_hash_2 = file_handler._hash(file_2.getvalue())

        urlopen_mock.side_effect = lambda url: {"url1": file_1, "url2": file_2}.get(url)
        event_data = {
            "1": [
                {"proposal_id": "1", "url": "url1", "hash": "wrong hash"},
            ],
            "2": [
                {"proposal_id": "2", "url": "url2", "hash": metadata_hash_2},
            ],
        }
        expected_proposals = [
            models.Proposal(
                id="1",
                dao_id="dao1",
                metadata_url="url1",
                metadata_hash="wrong hash",
                metadata=None,
                birth_block_number=10,
                setup_complete=True,
            ),
            models.Proposal(
                id="2",
                dao_id="dao2",
                metadata_url="url2",
                metadata_hash=metadata_hash_2,
                metadata=metadata_2,
                birth_block_number=10,
                setup_complete=True,
            ),
            models.Proposal(
                id="3",
                dao_id="dao3",
                metadata_url=None,
                metadata_hash=None,
                metadata=None,
                birth_block_number=10,
                setup_complete=False,
            ),
        ]

        with self.assertNumQueries(4):
            soroban_event_handler._set_proposal_metadata(event_data=event_data)

        urlopen_mock.assert_has_calls([call("url1"), call("url2")], any_order=True)
        logger_mock.error.assert_called_once_with("Hash mismatch while fetching Proposal metadata from provided url.")

        self.assertModelsEqual(models.Proposal.objects.order_by("id"), expected_proposals)

    @patch("core.tasks.slack_logger")
    @patch("core.file_handling.file_handler.FileHandler.download_metadata")
    def test__proposals_set_metadata_exception(self, download_metadata_mock, logger_mock):
        models.Proposal.objects.create(id="1", dao_id="dao1", birth_block_number=10)
        models.Proposal.objects.create(id="2", dao_id="dao2", birth_block_number=10)
        metadata_1 = {"a": 1}
        file_1 = BytesIO(json.dumps(metadata_1).encode())
        metadata_hash_1 = file_handler._hash(file_1.getvalue())
        metadata_2 = {"a": 2}
        file_2 = BytesIO(json.dumps(metadata_2).encode())
        metadata_hash_2 = file_handler._hash(file_2.getvalue())

        def download_metadata(url, **_):
            if url == "url1":
                raise Exception("roar")
            return metadata_2

        download_metadata_mock.side_effect = download_metadata
        event_data = {
            "1": [{"proposal_id": "1", "url": "url1", "hash": metadata_hash_1}],
            "2": [{"proposal_id": "2", "url": "url2", "hash": metadata_hash_2}],
        }

        expected_proposals = [
            models.Proposal(
                id="1",
                dao_id="dao1",
                metadata_url="url1",
                metadata_hash=metadata_hash_1,
                metadata=None,
                birth_block_number=10,
                setup_complete=True,
            ),
            models.Proposal(
                id="2",
                dao_id="dao2",
                metadata_url="url2",
                metadata_hash=metadata_hash_2,
                metadata=metadata_2,
                birth_block_number=10,
                setup_complete=True,
            ),
        ]

        with self.assertNumQueries(4):
            soroban_event_handler._set_proposal_metadata(event_data=event_data)

        download_metadata_mock.assert_has_calls(
            [
                call(url="url1", metadata_hash=metadata_hash_1),
                call(url="url2", metadata_hash=metadata_hash_2),
            ],
            any_order=True,
        )
        logger_mock.exception.assert_called_once_with(
            "Unexpected error while fetching Proposal metadata from provided url."
        )
        self.assertModelsEqual(models.Proposal.objects.order_by("id"), expected_proposals)

    @patch("core.tasks.slack_logger")
    @patch("core.file_handling.file_handler.FileHandler.download_metadata")
    def test__create_proposals_everything_failed(self, download_metadata_mock, logger_mock):
        models.Proposal.objects.create(id="1", dao_id="dao1", birth_block_number=10)
        models.Proposal.objects.create(id="2", dao_id="dao2", birth_block_number=10)
        metadata_1 = {"a": 1}
        file_1 = BytesIO(json.dumps(metadata_1).encode())
        metadata_hash_1 = file_handler._hash(file_1.getvalue())
        metadata_2 = {"a": 2}
        file_2 = BytesIO(json.dumps(metadata_2).encode())
        metadata_hash_2 = file_handler._hash(file_2.getvalue())

        download_metadata_mock.side_effect = Exception
        event_data = {
            "1": [
                {"proposal_id": "1", "url": "url1", "hash": metadata_hash_1},
            ],
            "2": [
                {"proposal_id": "2", "url": "url2", "hash": metadata_hash_2},
            ],
        }
        expected_proposals = [
            models.Proposal(
                id="1",
                dao_id="dao1",
                metadata_url="url1",
                metadata_hash=metadata_hash_1,
                metadata=None,
                birth_block_number=10,
                setup_complete=True,
            ),
            models.Proposal(
                id="2",
                dao_id="dao2",
                metadata_url="url2",
                metadata_hash=metadata_hash_2,
                metadata=None,
                birth_block_number=10,
                setup_complete=True,
            ),
        ]

        with self.assertNumQueries(3):
            soroban_event_handler._set_proposal_metadata(event_data=event_data)

        download_metadata_mock.assert_has_calls(
            [
                call(url="url1", metadata_hash=metadata_hash_1),
                call(url="url2", metadata_hash=metadata_hash_2),
            ],
            any_order=True,
        )
        logger_mock.exception.assert_has_calls(
            [call("Unexpected error while fetching Proposal metadata from provided url.")] * 2
        )
        self.assertModelsEqual(models.Proposal.objects.order_by("id"), expected_proposals)

    def test__register_votes(self):
        models.Account.objects.create(address="acc3")
        models.Dao.objects.create(id="dao3", contract_id="contract3", name="dao3 name", owner_id="acc3")
        models.Proposal.objects.create(id="prop1", dao_id="dao1", birth_block_number=10)
        models.Proposal.objects.create(id="prop2", dao_id="dao2", birth_block_number=10)
        models.Vote.objects.create(proposal_id="prop1", voter_id="acc1", voting_power=50, in_favor=None)
        models.Vote.objects.create(proposal_id="prop1", voter_id="acc2", voting_power=30, in_favor=None)
        models.Vote.objects.create(proposal_id="prop1", voter_id="acc3", voting_power=20, in_favor=None)
        models.Vote.objects.create(proposal_id="prop2", voter_id="acc3", voting_power=50, in_favor=None)
        models.Vote.objects.create(proposal_id="prop2", voter_id="acc2", voting_power=30, in_favor=None)
        models.Vote.objects.create(proposal_id="prop2", voter_id="acc1", voting_power=20, in_favor=None)
        event_data = {
            "c1": [
                {"proposal_id": "prop1", "voter_id": "acc1", "in_favor": True, "not": "interesting"},
                {"proposal_id": "prop1", "voter_id": "acc2", "in_favor": False, "not": "interesting"},
                {"proposal_id": "prop1", "voter_id": "acc3", "in_favor": False, "not": "interesting"},
                {"proposal_id": "prop2", "voter_id": "acc1", "in_favor": True, "not": "interesting"},
                {"proposal_id": "prop2", "voter_id": "acc2", "in_favor": True, "not": "interesting"},
            ],
        }
        expected_votes = [
            models.Vote(proposal_id="prop1", voter_id="acc1", voting_power=50, in_favor=True),
            models.Vote(proposal_id="prop1", voter_id="acc2", voting_power=30, in_favor=False),
            models.Vote(proposal_id="prop1", voter_id="acc3", voting_power=20, in_favor=False),
            models.Vote(proposal_id="prop2", voter_id="acc1", voting_power=20, in_favor=True),
            models.Vote(proposal_id="prop2", voter_id="acc2", voting_power=30, in_favor=True),
            models.Vote(proposal_id="prop2", voter_id="acc3", voting_power=50, in_favor=None),
        ]

        with self.assertNumQueries(2):
            soroban_event_handler._register_votes(event_data=event_data)

        self.assertModelsEqual(
            models.Vote.objects.order_by("proposal_id", "voter_id"),
            expected_votes,
            ignore_fields=("created_at", "updated_at", "id"),
        )

    def test__update_proposal_status(self):
        models.Proposal.objects.create(id="prop1", dao_id="dao1", birth_block_number=10)
        models.Proposal.objects.create(id="prop2", dao_id="dao1", birth_block_number=10)
        models.Proposal.objects.create(id="prop3", dao_id="dao2", birth_block_number=10)
        models.Proposal.objects.create(id="prop4", dao_id="dao2", birth_block_number=10)
        models.Proposal.objects.create(id="prop5", dao_id="dao2", birth_block_number=10)
        # not changed
        models.Proposal.objects.create(id="prop6", dao_id="dao1", birth_block_number=10)
        models.Proposal.objects.create(id="prop7", dao_id="dao2", birth_block_number=10)
        event_data = {
            "c1": [
                {"proposal_id": "prop1", "status": ["Accepted"]},
                {"proposal_id": "prop3", "status": ["Accepted"]},
                {"proposal_id": "prop4", "status": ["Implemented"]},
                {"proposal_id": "prop2", "status": ["Rejected"]},
                {"proposal_id": "prop5", "status": ["Rejected"]},
            ],
        }
        expected_proposals = [
            models.Proposal(id="prop1", dao_id="dao1", status=models.ProposalStatus.PENDING, birth_block_number=10),
            models.Proposal(id="prop2", dao_id="dao1", status=models.ProposalStatus.REJECTED, birth_block_number=10),
            models.Proposal(id="prop3", dao_id="dao2", status=models.ProposalStatus.PENDING, birth_block_number=10),
            models.Proposal(id="prop4", dao_id="dao2", status=models.ProposalStatus.IMPLEMENTED, birth_block_number=10),
            models.Proposal(id="prop5", dao_id="dao2", status=models.ProposalStatus.REJECTED, birth_block_number=10),
            models.Proposal(id="prop6", dao_id="dao1", status=models.ProposalStatus.RUNNING, birth_block_number=10),
            models.Proposal(id="prop7", dao_id="dao2", status=models.ProposalStatus.RUNNING, birth_block_number=10),
        ]

        with self.assertNumQueries(2):
            soroban_event_handler._update_proposal_status(event_data=event_data)

        self.assertModelsEqual(models.Proposal.objects.order_by("id"), expected_proposals)

    def test__fault_proposals(self):
        models.Proposal.objects.create(id="prop1", dao_id="dao1", birth_block_number=10)
        models.Proposal.objects.create(id="prop2", dao_id="dao1", birth_block_number=10)
        models.Proposal.objects.create(id="prop3", dao_id="dao2", birth_block_number=10)
        # not changed
        models.Proposal.objects.create(id="prop4", dao_id="dao1", birth_block_number=10)
        models.Proposal.objects.create(id="prop5", dao_id="dao2", birth_block_number=10)
        event_data = {
            "c1": [
                {"proposal_id": "prop1", "reason": "reason 1", "not": "interesting"},
                {"proposal_id": "prop2", "reason": "reason 2", "not": "interesting"},
                {"proposal_id": "prop3", "reason": "reason 3", "not": "interesting"},
            ]
        }
        expected_proposals = [
            models.Proposal(
                id="prop1", dao_id="dao1", fault="reason 1", status=models.ProposalStatus.FAULTED, birth_block_number=10
            ),
            models.Proposal(
                id="prop2", dao_id="dao1", fault="reason 2", status=models.ProposalStatus.FAULTED, birth_block_number=10
            ),
            models.Proposal(
                id="prop3", dao_id="dao2", fault="reason 3", status=models.ProposalStatus.FAULTED, birth_block_number=10
            ),
            models.Proposal(id="prop4", dao_id="dao1", status=models.ProposalStatus.RUNNING, birth_block_number=10),
            models.Proposal(id="prop5", dao_id="dao2", status=models.ProposalStatus.RUNNING, birth_block_number=10),
        ]

        with self.assertNumQueries(2):
            soroban_event_handler._fault_proposals(event_data=event_data)

        self.assertModelsEqual(models.Proposal.objects.order_by("id"), expected_proposals)

    def test_no_items(self):
        funcs = (
            soroban_event_handler._create_daos,
            soroban_event_handler._delete_daos,
            soroban_event_handler._transfer_dao_ownerships,
            soroban_event_handler._set_dao_metadata,
            soroban_event_handler._create_assets,
            soroban_event_handler._mint_tokens,
            soroban_event_handler._transfer_assets,
            soroban_event_handler._dao_set_governances,
            soroban_event_handler._create_proposals,
            soroban_event_handler._set_proposal_metadata,
            soroban_event_handler._register_votes,
            soroban_event_handler._update_proposal_status,
            soroban_event_handler._fault_proposals,
        )
        for func in funcs:
            with self.assertNumQueries(0):
                func(event_data={}, block=None)

    @patch("core.event_handler.SorobanEventHandler._create_daos")
    @patch("core.event_handler.SorobanEventHandler._delete_daos")
    @patch("core.event_handler.SorobanEventHandler._transfer_dao_ownerships")
    @patch("core.event_handler.SorobanEventHandler._set_dao_metadata")
    @patch("core.event_handler.SorobanEventHandler._create_assets")
    @patch("core.event_handler.SorobanEventHandler._mint_tokens")
    @patch("core.event_handler.SorobanEventHandler._transfer_assets")
    @patch("core.event_handler.SorobanEventHandler._dao_set_governances")
    @patch("core.event_handler.SorobanEventHandler._create_proposals")
    @patch("core.event_handler.SorobanEventHandler._set_proposal_metadata")
    @patch("core.event_handler.SorobanEventHandler._register_votes")
    @patch("core.event_handler.SorobanEventHandler._update_proposal_status")
    @patch("core.event_handler.SorobanEventHandler._fault_proposals")
    @patch("core.event_handler.logger")
    @data(
        # topics, expected func call
        (["DAO", "created"], "_create_daos"),
        (["DAO", "destroyed"], "_delete_daos"),
        (["DAO", "new_owner"], "_transfer_dao_ownerships"),
        (["DAO", "meta_set"], "_set_dao_metadata"),
        (["ASSET", "created"], "_create_assets"),
        (["ASSET", "minted"], "_mint_tokens"),
        (["ASSET", "transfer"], "_transfer_assets"),
        (["PROPOSAL", "conf_set"], "_dao_set_governances"),
        (["PROPOSAL", "created"], "_create_proposals"),
        (["PROPOSAL", "meta_set"], "_set_proposal_metadata"),
        (["PROPOSAL", "vote_cast"], "_register_votes"),
        (["PROPOSAL", "state_upd"], "_update_proposal_status"),
        (["PROPOSAL", "faulted"], "_fault_proposals"),
    )
    def test_execute_actions(
        self,
        case,
        logger_mock,
        fault_proposals_mock,
        update_proposal_status_mock,
        register_votes_mock,
        set_proposal_metadata_mock,
        create_proposals_mock,
        dao_set_governances_mock,
        transfer_assets_mock,
        mint_tokens_mock,
        create_assets_mock,
        set_dao_metadata_mock,
        transfer_dao_ownerships_mock,
        delete_daos_mock,
        create_daos_mock,
    ):
        topics, expected_func_call = case
        event_data = [["c1", "e1", topics, {"d": 1}]]
        block = models.Block.objects.create(number=0, event_data=event_data)
        func_to_mock = {
            "_create_daos": create_daos_mock,
            "_transfer_dao_ownerships": transfer_dao_ownerships_mock,
            "_delete_daos": delete_daos_mock,
            "_set_dao_metadata": set_dao_metadata_mock,
            "_create_assets": create_assets_mock,
            "_mint_tokens": mint_tokens_mock,
            "_transfer_assets": transfer_assets_mock,
            "_dao_set_governances": dao_set_governances_mock,
            "_create_proposals": create_proposals_mock,
            "_set_proposal_metadata": set_proposal_metadata_mock,
            "_register_votes": register_votes_mock,
            "_update_proposal_status": update_proposal_status_mock,
            "_fault_proposals": fault_proposals_mock,
        }

        with self.assertNumQueries(3):
            SorobanEventHandler().execute_actions(block=block)

        contract_id, event_id, topics, vals = event_data[0]
        logger_mock.info.has_calls(
            call("Executing event_data... Block number: 0"),
            call(f"Contract ID: {contract_id} | Event ID: {event_id} | Topics: {topics} | Values: {vals}"),
        )
        args = {"c1": [{"d": 1}]}
        func_to_mock.pop(expected_func_call).assert_called_once_with(event_data=args, block=block)
        for mock in func_to_mock.values():
            mock.assert_not_called()
        block.refresh_from_db()
        self.assertTrue(block.executed)
        self.assertEqual(cache.get("current_block_number"), 0)

    @patch("core.event_handler.logger")
    @patch("core.event_handler.slack_logger")
    @patch("core.event_handler.SorobanEventHandler._create_daos")
    def test_execute_actions_db_error(self, action_mock, slack_logger_mock, logger_mock):
        block = models.Block.objects.create(number=0, event_data=[["c1", "e1", ["DAO", "created"], {"d": 1}]])
        action_mock.side_effect = IntegrityError

        with self.assertNumQueries(3), self.assertRaises(ParseBlockException):
            SorobanEventHandler().execute_actions(block)

        block.refresh_from_db()
        self.assertFalse(block.executed)
        action_mock.assert_called_once_with(event_data={"c1": [{"d": 1}]}, block=block)
        self.assertExactCalls(
            logger_mock.info,
            [
                call("Executing event_data... Block number: 0"),
                call("Contract ID: c1 | Event ID: e1 | Topics: ['DAO', 'created'] | Values: {'d': 1}"),
            ],
        )
        slack_logger_mock.exception.assert_called_once_with("IntegrityError during block execution. Block number: 0.")

    @patch("core.event_handler.logger")
    @patch("core.event_handler.slack_logger")
    @patch("core.event_handler.SorobanEventHandler._delete_daos")
    def test_execute_actions_unexpected_error(self, action_mock, slack_logger_mock, logger_mock):
        block = models.Block.objects.create(number=0, event_data=[["c1", "e1", ["DAO", "destroyed"], {"d": 1}]])
        action_mock.side_effect = Exception

        with self.assertNumQueries(3), self.assertRaises(ParseBlockException):
            SorobanEventHandler().execute_actions(block)

        block.refresh_from_db()
        self.assertFalse(block.executed)
        action_mock.assert_called_once_with(event_data={"c1": [{"d": 1}]}, block=block)
        self.assertExactCalls(
            logger_mock.info,
            [
                call("Executing event_data... Block number: 0"),
                call("Contract ID: c1 | Event ID: e1 | Topics: ['DAO', 'destroyed'] | Values: {'d': 1}"),
            ],
        )
        slack_logger_mock.exception.assert_called_once_with("Unexpected error during block execution. Block number: 0.")

    @patch("core.event_handler.logger")
    def test_execute_actions_not_implemented(self, logger_mock):
        block = models.Block.objects.create(number=0, event_data=[["c1", "e1", ["DAO", "crangled"], {"d": 1}]])

        with self.assertNumQueries(3):
            SorobanEventHandler().execute_actions(block)

        block.refresh_from_db()
        self.assertTrue(block.executed)
        logger_mock.error.assert_called_once_with(
            "NotImplementedError during block execution. Block number: 0. "
            "No action defined for topics: ('DAO', 'crangled')."
        )
