import json
import random
from io import BytesIO
from unittest.mock import call, patch

from django.core.cache import cache
from django.db import IntegrityError
from django.utils import timezone
from freezegun import freeze_time

from core import models
from core.event_handler import (
    ParseBlockException,
    SubstrateEventHandler,
    substrate_event_handler,
)
from core.file_handling.file_handler import file_handler
from core.tests.testcases import IntegrationTestCase


class EventHandlerTest(IntegrationTestCase):
    def test__create_accounts(self):
        block = models.Block.objects.create(
            hash="hash 0",
            number=0,
            event_data={
                "not": "interesting",
                "System": {
                    "not": "interesting",
                    "NewAccount": [
                        {"account": "acc1", "not": "interesting"},
                        {"account": "acc2"},
                    ],
                },
            },
        )
        expected_accs = [
            models.Account(address="acc1"),
            models.Account(address="acc2"),
        ]

        with self.assertNumQueries(1):
            substrate_event_handler._create_accounts(block)

        self.assertModelsEqual(models.Account.objects.all(), expected_accs)

    def test__create_daos(self):
        models.Account.objects.create(address="acc1")
        models.Account.objects.create(address="acc2")
        block = models.Block.objects.create(
            hash="hash 0",
            number=0,
            extrinsic_data={
                "not": "interesting",
                "DaoCore": {
                    "create_dao": [
                        {"dao_id": "dao1", "dao_name": "dao1 name", "not": "interesting"},
                        {"dao_id": "dao2", "dao_name": "dao2 name"},
                        # should not be created cause of missing corresponding event
                        {"dao_id": "dao3", "dao_name": "dao3 name"},
                    ]
                },
            },
            event_data={
                "not": "interesting",
                "DaoCore": {
                    "DaoCreated": [
                        {"owner": "acc1", "dao_id": "dao1", "not": "interesting"},
                        {"owner": "acc2", "dao_id": "dao2", "not": "interesting"},
                    ]
                },
            },
        )
        expected_daos = [
            models.Dao(id="dao1", name="dao1 name", owner_id="acc1", creator_id="acc1"),
            models.Dao(id="dao2", name="dao2 name", owner_id="acc2", creator_id="acc2"),
        ]

        with self.assertNumQueries(1):
            substrate_event_handler._create_daos(block)

        self.assertModelsEqual(models.Dao.objects.order_by("id"), expected_daos)

    def test__transfer_dao_ownerships(self):
        models.Account.objects.create(address="acc1")
        models.Account.objects.create(address="acc2")
        models.Dao.objects.create(id="dao1", name="dao1 name", owner_id="acc1", creator_id="acc1")
        models.Dao.objects.create(id="dao2", name="dao2 name", owner_id="acc2", creator_id="acc2")
        models.Dao.objects.create(id="dao3", name="dao3 name", owner_id="acc2", creator_id="acc2")
        models.Account.objects.create(address="acc3")
        block = models.Block.objects.create(
            hash="hash 0",
            number=0,
            extrinsic_data={
                "not": "interesting",
            },
            event_data={
                "not": "interesting",
                "DaoCore": {
                    "DaoOwnerChanged": [
                        {"new_owner": "acc3", "dao_id": "dao1", "not": "interesting"},
                        {"new_owner": "acc1", "dao_id": "dao2", "not": "interesting"},
                        {"new_owner": "acc4", "dao_id": "dao3", "not": "interesting"},
                    ]
                },
            },
        )
        expected_daos = [
            models.Dao(id="dao1", name="dao1 name", owner_id="acc3", creator_id="acc1", setup_complete=True),
            models.Dao(id="dao2", name="dao2 name", owner_id="acc1", creator_id="acc2", setup_complete=True),
            models.Dao(id="dao3", name="dao3 name", owner_id="acc4", creator_id="acc2", setup_complete=True),
        ]
        expected_accounts = [
            models.Account(address="acc1"),
            models.Account(address="acc2"),
            models.Account(address="acc3"),
            models.Account(address="acc4"),
        ]

        with self.assertNumQueries(3):
            substrate_event_handler._transfer_dao_ownerships(block)

        self.assertModelsEqual(models.Dao.objects.order_by("id"), expected_daos)
        self.assertModelsEqual(models.Account.objects.order_by("address"), expected_accounts)

    def test__delete_daos(self):
        models.Dao.objects.create(id="dao1", name="dao1 name", owner=models.Account.objects.create(address="acc1"))
        models.Dao.objects.create(id="dao2", name="dao2 name", owner=models.Account.objects.create(address="acc2"))
        models.Dao.objects.create(id="dao3", name="dao3 name", owner_id="acc1")
        block = models.Block.objects.create(
            hash="hash 0",
            number=0,
            event_data={
                "not": "interesting",
                "DaoCore": {
                    "DaoDestroyed": [
                        {"dao_id": "dao1", "not": "interesting"},
                        {"dao_id": "dao3", "not": "interesting"},
                    ]
                },
            },
        )
        expected_daos = [
            models.Dao(id="dao2", name="dao2 name", owner_id="acc2"),
        ]

        with self.assertNumQueries(5):
            substrate_event_handler._delete_daos(block)

        self.assertModelsEqual(models.Dao.objects.all(), expected_daos)

    def test__create_assets(self):
        models.Dao.objects.create(id="dao1", name="dao1 name", owner=models.Account.objects.create(address="acc1"))
        models.Dao.objects.create(id="dao2", name="dao2 name", owner=models.Account.objects.create(address="acc2"))
        block = models.Block.objects.create(
            hash="hash 0",
            number=0,
            event_data={
                "not": "interesting",
                "Assets": {
                    "not": "interesting",
                    "Issued": [
                        {"asset_id": 1, "total_supply": 100, "owner": "acc1", "not": "interesting"},
                        {"asset_id": 2, "total_supply": 200, "owner": "acc2", "not": "interesting"},
                    ],
                    "MetadataSet": [
                        {"name": "dao1 name", "symbol": "dao1", "asset_id": 1, "not": "interesting"},
                        {"name": "dao2 name", "symbol": "dao2", "asset_id": 2, "not": "interesting"},
                    ],
                },
            },
        )
        expected_assets = [
            models.Asset(id=1, total_supply=100, owner_id="acc1", dao_id="dao1"),
            models.Asset(id=2, total_supply=200, owner_id="acc2", dao_id="dao2"),
        ]
        expected_asset_holdings = [
            models.AssetHolding(asset_id=1, owner_id="acc1", balance=100),
            models.AssetHolding(asset_id=2, owner_id="acc2", balance=200),
        ]

        with self.assertNumQueries(2):
            substrate_event_handler._create_assets(block)

        self.assertModelsEqual(models.Asset.objects.all(), expected_assets)
        self.assertModelsEqual(
            models.AssetHolding.objects.all(), expected_asset_holdings, ignore_fields=("id", "created_at", "updated_at")
        )

    def test__transfer_assets(self):
        models.Account.objects.create(address="acc1")
        models.Account.objects.create(address="acc2")
        models.Account.objects.create(address="acc3")
        models.Dao.objects.create(id="dao1", name="dao1 name", owner_id="acc1")
        models.Dao.objects.create(id="dao2", name="dao2 name", owner_id="acc2")
        models.Dao.objects.create(id="dao3", name="dao3 name", owner_id="acc3")
        models.Dao.objects.create(id="dao4", name="dao4 name", owner_id="acc3")
        models.Asset.objects.create(id=1, total_supply=150, owner_id="acc1", dao_id="dao1"),
        models.Asset.objects.create(id=2, total_supply=250, owner_id="acc2", dao_id="dao2"),
        models.Asset.objects.create(id=3, total_supply=300, owner_id="acc3", dao_id="dao3"),
        models.Asset.objects.create(id=4, total_supply=400, owner_id="acc3", dao_id="dao4"),
        models.AssetHolding.objects.create(asset_id=1, owner_id="acc1", balance=100),
        models.AssetHolding.objects.create(asset_id=1, owner_id="acc3", balance=50),
        models.AssetHolding.objects.create(asset_id=2, owner_id="acc2", balance=200),
        models.AssetHolding.objects.create(asset_id=2, owner_id="acc3", balance=50),
        models.AssetHolding.objects.create(asset_id=3, owner_id="acc2", balance=50),
        models.AssetHolding.objects.create(asset_id=3, owner_id="acc3", balance=300),
        models.AssetHolding.objects.create(asset_id=4, owner_id="acc3", balance=400),
        transfers = [
            {"asset_id": 1, "amount": 10, "from": "acc1", "to": "acc2", "not": "interesting"},
            {"asset_id": 1, "amount": 15, "from": "acc1", "to": "acc2", "not": "interesting"},
            {"asset_id": 1, "amount": 25, "from": "acc3", "to": "acc2", "not": "interesting"},
            {"asset_id": 2, "amount": 20, "from": "acc2", "to": "acc1", "not": "interesting"},
            {"asset_id": 3, "amount": 50, "from": "acc3", "to": "acc2", "not": "interesting"},
        ]
        random.shuffle(transfers)  # order mustn't matter
        block = models.Block.objects.create(
            hash="hash 0",
            number=0,
            event_data={
                "not": "interesting",
                "Assets": {
                    "not": "interesting",
                    "Transferred": transfers,
                },
            },
        )

        with self.assertNumQueries(3):
            substrate_event_handler._transfer_assets(block)

        expected_asset_holdings = [
            models.AssetHolding(asset_id=1, owner_id="acc1", balance=75),  # 100 - 10 - 15
            models.AssetHolding(asset_id=1, owner_id="acc2", balance=50),  # 0 + 10 + 15 + 25
            models.AssetHolding(asset_id=1, owner_id="acc3", balance=25),  # 50 - 25
            models.AssetHolding(asset_id=2, owner_id="acc1", balance=20),  # 0 + 20
            models.AssetHolding(asset_id=2, owner_id="acc2", balance=180),  # 200 - 20
            models.AssetHolding(asset_id=2, owner_id="acc3", balance=50),  # 50
            models.AssetHolding(asset_id=3, owner_id="acc2", balance=100),  # 50 + 50
            models.AssetHolding(asset_id=3, owner_id="acc3", balance=250),  # 300 - 50
            models.AssetHolding(asset_id=4, owner_id="acc3", balance=400),  # 300
        ]
        self.assertModelsEqual(
            models.AssetHolding.objects.order_by("asset_id", "owner_id"),
            expected_asset_holdings,
            ignore_fields=("id", "created_at", "updated_at"),
        )

    @patch("core.file_handling.file_handler.urlopen")
    def test__set_dao_metadata(self, urlopen_mock):
        models.Account.objects.create(address="acc1")
        models.Account.objects.create(address="acc2")
        models.Account.objects.create(address="acc3")
        models.Dao.objects.create(id="dao1", name="dao1 name", owner_id="acc1")
        models.Dao.objects.create(id="dao2", name="dao2 name", owner_id="acc2")
        models.Dao.objects.create(id="dao3", name="dao3 name", owner_id="acc3")
        metadata_1 = {"a": 1}
        file_1 = BytesIO(json.dumps(metadata_1).encode())
        metadata_hash_1 = file_handler._hash(file_1.getvalue())
        metadata_2 = {"a": 2}
        file_2 = BytesIO(json.dumps(metadata_2).encode())
        metadata_hash_2 = file_handler._hash(file_2.getvalue())

        urlopen_mock.side_effect = lambda url: {"url1": file_1, "url2": file_2}.get(url)
        block = models.Block.objects.create(
            hash="hash 0",
            number=0,
            extrinsic_data={
                "not": "interesting",
                "DaoCore": {
                    "not": "interesting",
                    "set_metadata": [
                        {"dao_id": "dao1", "hash": metadata_hash_1, "meta": "url1", "not": "interesting"},
                        {"dao_id": "dao2", "hash": metadata_hash_2, "meta": "url2", "not": "interesting"},
                        # should not be updated cause of missing corresponding event
                        {"dao_id": "dao3", "hash": "hash33", "meta": "url3", "not": "interesting"},
                    ],
                },
            },
            event_data={
                "not": "interesting",
                "DaoCore": {
                    "not": "interesting",
                    "DaoMetadataSet": [
                        {"dao_id": "dao1", "not": "interesting"},
                        {"dao_id": "dao2", "not": "interesting"},
                    ],
                },
            },
        )
        expected_daos = [
            models.Dao(
                id="dao1",
                name="dao1 name",
                owner_id="acc1",
                metadata_hash=metadata_hash_1,
                metadata_url="url1",
                metadata=metadata_1,
            ),
            models.Dao(
                id="dao2",
                name="dao2 name",
                owner_id="acc2",
                metadata_hash=metadata_hash_2,
                metadata_url="url2",
                metadata=metadata_2,
            ),
            models.Dao(id="dao3", name="dao3 name", owner_id="acc3", metadata_hash=None, metadata_url=None),
        ]

        with self.assertNumQueries(2):
            substrate_event_handler._set_dao_metadata(block)

        urlopen_mock.assert_has_calls([call("url1"), call("url2")], any_order=True)
        self.assertModelsEqual(models.Dao.objects.order_by("id"), expected_daos)

    @patch("core.file_handling.file_handler.urlopen")
    @patch("core.tasks.logger")
    def test__set_dao_metadata_hash_mismatch(self, logger_mock, urlopen_mock):
        models.Account.objects.create(address="acc1")
        models.Account.objects.create(address="acc2")
        models.Account.objects.create(address="acc3")
        models.Dao.objects.create(id="dao1", name="dao1 name", owner_id="acc1")
        models.Dao.objects.create(id="dao2", name="dao2 name", owner_id="acc2")
        models.Dao.objects.create(id="dao3", name="dao3 name", owner_id="acc3")
        metadata_1 = {"a": 1}
        file_1 = BytesIO(json.dumps(metadata_1).encode())
        metadata_hash_1 = file_handler._hash(file_1.getvalue())
        metadata_2 = {"a": 2}
        file_2 = BytesIO(json.dumps(metadata_2).encode())

        urlopen_mock.side_effect = lambda url: {"url1": file_1, "url2": file_2}.get(url)

        block = models.Block.objects.create(
            hash="hash 0",
            number=0,
            extrinsic_data={
                "not": "interesting",
                "DaoCore": {
                    "not": "interesting",
                    "set_metadata": [
                        {"dao_id": "dao1", "hash": metadata_hash_1, "meta": "url1", "not": "interesting"},
                        {"dao_id": "dao2", "hash": "wrong hash", "meta": "url2", "not": "interesting"},
                        # should not be updated cause of missing corresponding event
                        {"dao_id": "dao3", "hash": "hash33", "meta": "url3", "not": "interesting"},
                    ],
                },
            },
            event_data={
                "not": "interesting",
                "DaoCore": {
                    "not": "interesting",
                    "DaoMetadataSet": [
                        {"dao_id": "dao1", "not": "interesting"},
                        {"dao_id": "dao2", "not": "interesting"},
                    ],
                },
            },
        )
        expected_daos = [
            models.Dao(
                id="dao1",
                name="dao1 name",
                owner_id="acc1",
                metadata_url="url1",
                metadata_hash=metadata_hash_1,
                metadata=metadata_1,
            ),
            models.Dao(id="dao2", name="dao2 name", owner_id="acc2", metadata_url="url2", metadata_hash="wrong hash"),
            models.Dao(id="dao3", name="dao3 name", owner_id="acc3"),
        ]

        with self.assertNumQueries(2):
            substrate_event_handler._set_dao_metadata(block)

        urlopen_mock.assert_has_calls([call("url1"), call("url2")], any_order=True)
        logger_mock.error.assert_called_once_with("Hash mismatch while fetching DAO metadata from provided url.")
        self.assertModelsEqual(models.Dao.objects.order_by("id"), expected_daos)

    @patch("core.file_handling.file_handler.FileHandler.download_metadata")
    @patch("core.tasks.logger")
    def test__set_dao_metadata_exception(self, logger_mock, download_metadata_mock):
        models.Account.objects.create(address="acc1")
        models.Account.objects.create(address="acc2")
        models.Account.objects.create(address="acc3")
        models.Dao.objects.create(id="dao1", name="dao1 name", owner_id="acc1")
        models.Dao.objects.create(id="dao2", name="dao2 name", owner_id="acc2")
        models.Dao.objects.create(id="dao3", name="dao3 name", owner_id="acc3")
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
        block = models.Block.objects.create(
            hash="hash 0",
            number=0,
            extrinsic_data={
                "not": "interesting",
                "DaoCore": {
                    "not": "interesting",
                    "set_metadata": [
                        {"dao_id": "dao1", "hash": metadata_hash_1, "meta": "url1", "not": "interesting"},
                        {"dao_id": "dao2", "hash": metadata_hash_2, "meta": "url2", "not": "interesting"},
                        # should not be updated cause of missing corresponding event
                        {"dao_id": "dao3", "hash": "hash33", "meta": "url3", "not": "interesting"},
                    ],
                },
            },
            event_data={
                "not": "interesting",
                "DaoCore": {
                    "not": "interesting",
                    "DaoMetadataSet": [
                        {"dao_id": "dao1", "not": "interesting"},
                        {"dao_id": "dao2", "not": "interesting"},
                    ],
                },
            },
        )
        expected_daos = [
            models.Dao(
                id="dao1",
                name="dao1 name",
                owner_id="acc1",
                metadata_url="url1",
                metadata_hash=metadata_hash_1,
            ),
            models.Dao(
                id="dao2",
                name="dao2 name",
                owner_id="acc2",
                metadata_url="url2",
                metadata_hash=metadata_hash_2,
                metadata=metadata_2,
            ),
            models.Dao(id="dao3", name="dao3 name", owner_id="acc3"),
        ]

        with self.assertNumQueries(2):
            substrate_event_handler._set_dao_metadata(block)

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
        models.Account.objects.create(address="acc1")
        models.Account.objects.create(address="acc2")
        models.Account.objects.create(address="acc3")
        models.Dao.objects.create(id="dao1", name="dao1 name", owner_id="acc1", metadata_hash="hash1")
        models.Dao.objects.create(id="dao2", name="dao2 name", owner_id="acc2", metadata_hash="hash2")
        models.Dao.objects.create(id="dao3", name="dao3 name", owner_id="acc3")

        block = models.Block.objects.create(
            hash="hash 0",
            number=0,
            extrinsic_data={
                "not": "interesting",
                "DaoCore": {
                    "not": "interesting",
                    "set_metadata": [
                        {"dao_id": "dao1", "hash": "hash1", "meta": "url1", "not": "interesting"},
                        {"dao_id": "dao2", "hash": "hash2", "meta": "url2", "not": "interesting"},
                        # should not be updated cause of missing corresponding event
                        {"dao_id": "dao3", "hash": "hash33", "meta": "url3", "not": "interesting"},
                    ],
                },
            },
            event_data={
                "not": "interesting",
                "DaoCore": {
                    "not": "interesting",
                    "DaoMetadataSet": [
                        {"dao_id": "dao1", "not": "interesting"},
                        {"dao_id": "dao2", "not": "interesting"},
                    ],
                },
            },
        )
        expected_daos = [
            models.Dao(id="dao1", name="dao1 name", owner_id="acc1", metadata_hash="hash1"),
            models.Dao(id="dao2", name="dao2 name", owner_id="acc2", metadata_hash="hash2"),
            models.Dao(id="dao3", name="dao3 name", owner_id="acc3"),
        ]

        with self.assertNumQueries(1):
            substrate_event_handler._set_dao_metadata(block)

        urlopen_mock.assert_not_called()
        self.assertModelsEqual(models.Dao.objects.order_by("id"), expected_daos)

    def test__dao_set_governance(self):
        models.Account.objects.create(address="acc1")
        models.Account.objects.create(address="acc2")
        models.Account.objects.create(address="acc3")
        models.Dao.objects.create(id="dao1", name="dao1 name", owner_id="acc1")
        models.Dao.objects.create(id="dao2", name="dao2 name", owner_id="acc2")
        models.Dao.objects.create(id="dao3", name="dao3 name", owner_id="acc3")

        block = models.Block.objects.create(
            hash="hash 0",
            number=0,
            extrinsic_data={
                "not": "interesting",
            },
            event_data={
                "not": "interesting",
                "Votes": {
                    "SetGovernanceMajorityVote": [
                        {
                            "dao_id": "dao1",
                            "proposal_duration": 1,
                            "proposal_token_deposit": 2,
                            "minimum_majority_per_1024": 3,
                        },
                        {
                            "dao_id": "dao2",
                            "proposal_duration": 4,
                            "proposal_token_deposit": 5,
                            "minimum_majority_per_1024": 6,
                        },
                    ]
                },
            },
        )
        expected_governances = [
            models.Governance(
                dao_id="dao1",
                proposal_duration=1,
                proposal_token_deposit=2,
                minimum_majority=3,
                type=models.GovernanceType.MAJORITY_VOTE,
            ),
            models.Governance(
                dao_id="dao2",
                proposal_duration=4,
                proposal_token_deposit=5,
                minimum_majority=6,
                type=models.GovernanceType.MAJORITY_VOTE,
            ),
        ]

        with self.assertNumQueries(2):
            substrate_event_handler._dao_set_governances(block)

        created_governances = models.Governance.objects.order_by("dao_id")
        self.assertModelsEqual(
            created_governances, expected_governances, ignore_fields=["id", "created_at", "updated_at"]
        )
        expected_daos = [
            models.Dao(id="dao1", name="dao1 name", owner_id="acc1", governance=created_governances[0]),
            models.Dao(id="dao2", name="dao2 name", owner_id="acc2", governance=created_governances[1]),
            models.Dao(id="dao3", name="dao3 name", owner_id="acc3", governance=None),
        ]
        self.assertModelsEqual(models.Dao.objects.order_by("id"), expected_daos)

    def test__create_proposals(self):
        models.Account.objects.create(address="acc1")
        models.Account.objects.create(address="acc2")
        models.Account.objects.create(address="acc3")
        models.Dao.objects.create(id="dao1", name="dao1 name", owner_id="acc1")
        models.Dao.objects.create(id="dao2", name="dao2 name", owner_id="acc2")
        models.Dao.objects.create(id="dao3", name="dao3 name", owner_id="acc3")
        models.Governance.objects.create(
            dao_id="dao1",
            type=models.GovernanceType.MAJORITY_VOTE,
            proposal_duration=10,
            proposal_token_deposit=10,
            minimum_majority=10,
        )
        models.Governance.objects.create(
            dao_id="dao2",
            type=models.GovernanceType.MAJORITY_VOTE,
            proposal_duration=15,
            proposal_token_deposit=10,
            minimum_majority=10,
        )
        models.Governance.objects.create(
            dao_id="dao3",
            type=models.GovernanceType.MAJORITY_VOTE,
            proposal_duration=20,
            proposal_token_deposit=10,
            minimum_majority=10,
        )
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

        block = models.Block.objects.create(
            hash="hash 0",
            number=123,
            extrinsic_data={
                "not": "interesting",
                "Votes": {
                    "not": "interesting",
                    "create_proposal": [
                        {"dao_id": "dao1", "not": "interesting"},
                        {"dao_id": "dao2", "not": "interesting"},
                        # should not be updated cause of missing corresponding event
                        {"dao_id": "dao3", "not": "interesting"},
                    ],
                },
            },
            event_data={
                "not": "interesting",
                "Votes": {
                    "not": "interesting",
                    "ProposalCreated": [
                        {"proposal_id": "prop1", "dao_id": "dao1", "creator": "acc1", "not": "interesting"},
                        {"proposal_id": "prop2", "dao_id": "dao2", "creator": "acc2", "not": "interesting"},
                    ],
                },
            },
        )
        time = timezone.now()
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

        with self.assertNumQueries(4), freeze_time(time):
            substrate_event_handler._create_proposals(block)

        self.assertModelsEqual(models.Proposal.objects.order_by("id"), expected_proposals)
        self.assertModelsEqual(
            models.Vote.objects.order_by("proposal_id", "-voting_power"),
            expected_votes,
            ignore_fields=("created_at", "updated_at", "id"),
        )

    @patch("core.file_handling.file_handler.urlopen")
    def test__set_proposal_metadata(self, urlopen_mock):
        models.Account.objects.create(address="acc1")
        models.Account.objects.create(address="acc2")
        models.Dao.objects.create(id="dao1", name="dao1 name", owner_id="acc1")
        models.Dao.objects.create(id="dao2", name="dao2 name", owner_id="acc2")
        models.Proposal.objects.create(id="1", dao_id="dao1", birth_block_number=10)
        models.Proposal.objects.create(id="2", dao_id="dao2", birth_block_number=10)
        metadata_1 = {"a": 1}
        file_1 = BytesIO(json.dumps(metadata_1).encode())
        metadata_hash_1 = file_handler._hash(file_1.getvalue())
        metadata_2 = {"a": 2}
        file_2 = BytesIO(json.dumps(metadata_2).encode())
        metadata_hash_2 = file_handler._hash(file_2.getvalue())

        urlopen_mock.side_effect = lambda url: {"url1": file_1, "url2": file_2}.get(url)
        block = models.Block.objects.create(
            hash="hash 0",
            number=0,
            extrinsic_data={
                "not": "interesting",
                "Votes": {
                    "not": "interesting",
                    "set_metadata": [
                        {
                            "proposal_id": 1,
                            "hash": metadata_hash_1,
                            "meta": "url1",
                            "not": "interesting",
                        },
                        {
                            "dao_id": "dao2",
                            "proposal_id": 2,
                            "hash": metadata_hash_2,
                            "meta": "url2",
                            "not": "interesting",
                        },
                        # should not be updated cause of missing corresponding event
                        {
                            "dao_id": "dao3",
                            "proposal_id": 3,
                            "hash": metadata_hash_2,
                            "meta": "url2",
                            "not": "interesting",
                        },
                    ],
                },
            },
            event_data={
                "not": "interesting",
                "Votes": {
                    "not": "interesting",
                    "ProposalMetadataSet": [
                        {"proposal_id": 1, "not": "interesting"},
                        {"proposal_id": 2, "not": "interesting"},
                    ],
                },
            },
        )
        expected_proposals = [
            models.Proposal(
                id="1",
                dao_id="dao1",
                metadata_url="url1",
                metadata_hash=metadata_hash_1,
                metadata=metadata_1,
                birth_block_number=10,
            ),
            models.Proposal(
                id="2",
                dao_id="dao2",
                metadata_url="url2",
                metadata_hash=metadata_hash_2,
                metadata=metadata_2,
                birth_block_number=10,
            ),
        ]
        with self.assertNumQueries(4):
            substrate_event_handler._set_proposal_metadata(block)

        urlopen_mock.assert_has_calls([call("url1"), call("url2")], any_order=True)
        self.assertModelsEqual(models.Proposal.objects.order_by("id"), expected_proposals)

    @patch("core.tasks.logger")
    @patch("core.file_handling.file_handler.urlopen")
    def test__proposal_set_metadata_hash_mismatch(self, urlopen_mock, logger_mock):
        models.Account.objects.create(address="acc1")
        models.Account.objects.create(address="acc2")
        models.Account.objects.create(address="acc3")
        models.Dao.objects.create(id="dao1", name="dao1 name", owner_id="acc1")
        models.Dao.objects.create(id="dao2", name="dao2 name", owner_id="acc2")
        models.Dao.objects.create(id="dao3", name="dao3 name", owner_id="acc3")
        models.Proposal.objects.create(id="1", dao_id="dao1", birth_block_number=10)
        models.Proposal.objects.create(id="2", dao_id="dao2", birth_block_number=10)
        models.Proposal.objects.create(id="3", dao_id="dao3", birth_block_number=10)
        metadata_1 = {"a": 1}
        file_1 = BytesIO(json.dumps(metadata_1).encode())
        metadata_2 = {"a": 2}
        file_2 = BytesIO(json.dumps(metadata_2).encode())
        metadata_hash_2 = file_handler._hash(file_2.getvalue())

        urlopen_mock.side_effect = lambda url: {"url1": file_1, "url2": file_2}.get(url)
        block = models.Block.objects.create(
            hash="hash 0",
            number=0,
            extrinsic_data={
                "not": "interesting",
                "Votes": {
                    "not": "interesting",
                    "set_metadata": [
                        {
                            "proposal_id": 1,
                            "hash": "wrong hash",
                            "meta": "url1",
                            "not": "interesting",
                        },
                        {
                            "proposal_id": 2,
                            "hash": metadata_hash_2,
                            "meta": "url2",
                            "not": "interesting",
                        },
                        # should not be updated cause of missing corresponding event
                        {
                            "proposal_id": 3,
                            "hash": metadata_hash_2,
                            "meta": "url2",
                            "not": "interesting",
                        },
                    ],
                },
            },
            event_data={
                "not": "interesting",
                "Votes": {
                    "not": "interesting",
                    "ProposalMetadataSet": [
                        {"proposal_id": 1, "not": "interesting"},
                        {"proposal_id": 2, "not": "interesting"},
                    ],
                },
            },
        )
        expected_proposals = [
            models.Proposal(
                id="1",
                dao_id="dao1",
                metadata_url="url1",
                metadata_hash="wrong hash",
                metadata=None,
                birth_block_number=10,
            ),
            models.Proposal(
                id="2",
                dao_id="dao2",
                metadata_url="url2",
                metadata_hash=metadata_hash_2,
                metadata=metadata_2,
                birth_block_number=10,
            ),
            models.Proposal(
                id="3",
                dao_id="dao3",
                metadata_url=None,
                metadata_hash=None,
                metadata=None,
                birth_block_number=10,
            ),
        ]

        with self.assertNumQueries(4):
            substrate_event_handler._set_proposal_metadata(block)

        urlopen_mock.assert_has_calls([call("url1"), call("url2")], any_order=True)
        logger_mock.error.assert_called_once_with("Hash mismatch while fetching Proposal metadata from provided url.")

        self.assertModelsEqual(models.Proposal.objects.order_by("id"), expected_proposals)

    @patch("core.tasks.logger")
    @patch("core.file_handling.file_handler.FileHandler.download_metadata")
    def test__proposals_set_metadata_exception(self, download_metadata_mock, logger_mock):
        models.Account.objects.create(address="acc1")
        models.Account.objects.create(address="acc2")
        models.Dao.objects.create(id="dao1", name="dao1 name", owner_id="acc1")
        models.Dao.objects.create(id="dao2", name="dao2 name", owner_id="acc2")
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
        block = models.Block.objects.create(
            hash="hash 0",
            number=0,
            extrinsic_data={
                "not": "interesting",
                "Votes": {
                    "not": "interesting",
                    "set_metadata": [
                        {
                            "dao_id": "dao1",
                            "proposal_id": 1,
                            "hash": metadata_hash_1,
                            "meta": "url1",
                            "not": "interesting",
                        },
                        {
                            "dao_id": "dao2",
                            "proposal_id": 2,
                            "hash": metadata_hash_2,
                            "meta": "url2",
                            "not": "interesting",
                        },
                    ],
                },
            },
            event_data={
                "not": "interesting",
                "Votes": {
                    "not": "interesting",
                    "ProposalMetadataSet": [
                        {"proposal_id": 1, "not": "interesting"},
                        {"proposal_id": 2, "not": "interesting"},
                    ],
                },
            },
        )
        expected_proposals = [
            models.Proposal(
                id="1",
                dao_id="dao1",
                metadata_url="url1",
                metadata_hash=metadata_hash_1,
                metadata=None,
                birth_block_number=10,
            ),
            models.Proposal(
                id="2",
                dao_id="dao2",
                metadata_url="url2",
                metadata_hash=metadata_hash_2,
                metadata=metadata_2,
                birth_block_number=10,
            ),
        ]

        with self.assertNumQueries(4):
            substrate_event_handler._set_proposal_metadata(block)

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

    @patch("core.tasks.logger")
    @patch("core.file_handling.file_handler.FileHandler.download_metadata")
    def test__create_proposals_everything_failed(self, download_metadata_mock, logger_mock):
        models.Account.objects.create(address="acc1")
        models.Account.objects.create(address="acc2")
        models.Dao.objects.create(id="dao1", name="dao1 name", owner_id="acc1")
        models.Dao.objects.create(id="dao2", name="dao2 name", owner_id="acc2")
        models.Proposal.objects.create(id="1", dao_id="dao1", birth_block_number=10)
        models.Proposal.objects.create(id="2", dao_id="dao2", birth_block_number=10)
        metadata_1 = {"a": 1}
        file_1 = BytesIO(json.dumps(metadata_1).encode())
        metadata_hash_1 = file_handler._hash(file_1.getvalue())
        metadata_2 = {"a": 2}
        file_2 = BytesIO(json.dumps(metadata_2).encode())
        metadata_hash_2 = file_handler._hash(file_2.getvalue())

        download_metadata_mock.side_effect = Exception
        block = models.Block.objects.create(
            hash="hash 0",
            number=0,
            extrinsic_data={
                "not": "interesting",
                "Votes": {
                    "not": "interesting",
                    "set_metadata": [
                        {
                            "dao_id": "dao1",
                            "proposal_id": "1",
                            "hash": metadata_hash_1,
                            "meta": "url1",
                            "not": "interesting",
                        },
                        {
                            "dao_id": "dao2",
                            "proposal_id": "2",
                            "hash": metadata_hash_2,
                            "meta": "url2",
                            "not": "interesting",
                        },
                    ],
                },
            },
            event_data={
                "not": "interesting",
                "Votes": {
                    "not": "interesting",
                    "ProposalMetadataSet": [
                        {"proposal_id": "1", "not": "interesting"},
                        {"proposal_id": "2", "not": "interesting"},
                    ],
                },
            },
        )
        expected_proposals = [
            models.Proposal(
                id="1",
                dao_id="dao1",
                metadata_url="url1",
                metadata_hash=metadata_hash_1,
                metadata=None,
                birth_block_number=10,
            ),
            models.Proposal(
                id="2",
                dao_id="dao2",
                metadata_url="url2",
                metadata_hash=metadata_hash_2,
                metadata=None,
                birth_block_number=10,
            ),
        ]

        with self.assertNumQueries(3):
            substrate_event_handler._set_proposal_metadata(block)

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
        models.Account.objects.create(address="acc1")
        models.Account.objects.create(address="acc2")
        models.Account.objects.create(address="acc3")
        models.Dao.objects.create(id="dao1", name="dao1 name", owner_id="acc1")
        models.Dao.objects.create(id="dao2", name="dao2 name", owner_id="acc2")
        models.Dao.objects.create(id="dao3", name="dao3 name", owner_id="acc3")
        models.Proposal.objects.create(id="prop1", dao_id="dao1", birth_block_number=10)
        models.Proposal.objects.create(id="prop2", dao_id="dao2", birth_block_number=10)
        models.Vote.objects.create(proposal_id="prop1", voter_id="acc1", voting_power=50, in_favor=None)
        models.Vote.objects.create(proposal_id="prop1", voter_id="acc2", voting_power=30, in_favor=None)
        models.Vote.objects.create(proposal_id="prop1", voter_id="acc3", voting_power=20, in_favor=None)
        models.Vote.objects.create(proposal_id="prop2", voter_id="acc3", voting_power=50, in_favor=None)
        models.Vote.objects.create(proposal_id="prop2", voter_id="acc2", voting_power=30, in_favor=None)
        models.Vote.objects.create(proposal_id="prop2", voter_id="acc1", voting_power=20, in_favor=None)
        block = models.Block.objects.create(
            hash="hash 0",
            number=0,
            extrinsic_data={
                "not": "interesting",
            },
            event_data={
                "not": "interesting",
                "Votes": {
                    "not": "interesting",
                    "VoteCast": [
                        {"proposal_id": "prop1", "voter": "acc1", "in_favor": True, "not": "interesting"},
                        {"proposal_id": "prop1", "voter": "acc2", "in_favor": False, "not": "interesting"},
                        {"proposal_id": "prop1", "voter": "acc3", "in_favor": False, "not": "interesting"},
                        {"proposal_id": "prop2", "voter": "acc1", "in_favor": True, "not": "interesting"},
                        {"proposal_id": "prop2", "voter": "acc2", "in_favor": True, "not": "interesting"},
                    ],
                },
            },
        )
        expected_votes = [
            models.Vote(proposal_id="prop1", voter_id="acc1", voting_power=50, in_favor=True),
            models.Vote(proposal_id="prop1", voter_id="acc2", voting_power=30, in_favor=False),
            models.Vote(proposal_id="prop1", voter_id="acc3", voting_power=20, in_favor=False),
            models.Vote(proposal_id="prop2", voter_id="acc1", voting_power=20, in_favor=True),
            models.Vote(proposal_id="prop2", voter_id="acc2", voting_power=30, in_favor=True),
            models.Vote(proposal_id="prop2", voter_id="acc3", voting_power=50, in_favor=None),
        ]

        with self.assertNumQueries(2):
            substrate_event_handler._register_votes(block)

        self.assertModelsEqual(
            models.Vote.objects.order_by("proposal_id", "voter_id"),
            expected_votes,
            ignore_fields=("created_at", "updated_at", "id"),
        )

    def test__finalize_proposals(self):
        models.Account.objects.create(address="acc1")
        models.Account.objects.create(address="acc2")
        models.Dao.objects.create(id="dao1", name="dao1 name", owner_id="acc1")
        models.Dao.objects.create(id="dao2", name="dao2 name", owner_id="acc2")
        models.Proposal.objects.create(id="prop1", dao_id="dao1", birth_block_number=10)
        models.Proposal.objects.create(id="prop2", dao_id="dao1", birth_block_number=10)
        models.Proposal.objects.create(id="prop3", dao_id="dao2", birth_block_number=10)
        models.Proposal.objects.create(id="prop4", dao_id="dao2", birth_block_number=10)
        models.Proposal.objects.create(id="prop5", dao_id="dao2", birth_block_number=10)
        # not changed
        models.Proposal.objects.create(id="prop6", dao_id="dao1", birth_block_number=10)
        models.Proposal.objects.create(id="prop7", dao_id="dao2", birth_block_number=10)
        block = models.Block.objects.create(
            hash="hash 0",
            number=0,
            extrinsic_data={
                "not": "interesting",
            },
            event_data={
                "not": "interesting",
                "Votes": {
                    "not": "interesting",
                    "ProposalAccepted": [
                        {"proposal_id": "prop1", "not": "interesting"},
                        {"proposal_id": "prop3", "not": "interesting"},
                        {"proposal_id": "prop4", "not": "interesting"},
                    ],
                    "ProposalRejected": [
                        {"proposal_id": "prop2", "not": "interesting"},
                        {"proposal_id": "prop5", "not": "interesting"},
                    ],
                },
            },
        )
        expected_proposals = [
            models.Proposal(id="prop1", dao_id="dao1", status=models.ProposalStatus.PENDING, birth_block_number=10),
            models.Proposal(id="prop2", dao_id="dao1", status=models.ProposalStatus.REJECTED, birth_block_number=10),
            models.Proposal(id="prop3", dao_id="dao2", status=models.ProposalStatus.PENDING, birth_block_number=10),
            models.Proposal(id="prop4", dao_id="dao2", status=models.ProposalStatus.PENDING, birth_block_number=10),
            models.Proposal(id="prop5", dao_id="dao2", status=models.ProposalStatus.REJECTED, birth_block_number=10),
            models.Proposal(id="prop6", dao_id="dao1", status=models.ProposalStatus.RUNNING, birth_block_number=10),
            models.Proposal(id="prop7", dao_id="dao2", status=models.ProposalStatus.RUNNING, birth_block_number=10),
        ]

        with self.assertNumQueries(2):
            substrate_event_handler._finalize_proposals(block)

        self.assertModelsEqual(models.Proposal.objects.order_by("id"), expected_proposals)

    def test__fault_proposals(self):
        models.Account.objects.create(address="acc1")
        models.Account.objects.create(address="acc2")
        models.Dao.objects.create(id="dao1", name="dao1 name", owner_id="acc1")
        models.Dao.objects.create(id="dao2", name="dao2 name", owner_id="acc2")
        models.Proposal.objects.create(id="prop1", dao_id="dao1", birth_block_number=10)
        models.Proposal.objects.create(id="prop2", dao_id="dao1", birth_block_number=10)
        models.Proposal.objects.create(id="prop3", dao_id="dao2", birth_block_number=10)
        # not changed
        models.Proposal.objects.create(id="prop4", dao_id="dao1", birth_block_number=10)
        models.Proposal.objects.create(id="prop5", dao_id="dao2", birth_block_number=10)
        block = models.Block.objects.create(
            hash="hash 0",
            number=0,
            extrinsic_data={
                "not": "interesting",
            },
            event_data={
                "not": "interesting",
                "Votes": {
                    "not": "interesting",
                    "ProposalFaulted": [
                        {"proposal_id": "prop1", "reason": "reason 1", "not": "interesting"},
                        {"proposal_id": "prop2", "reason": "reason 2", "not": "interesting"},
                        {"proposal_id": "prop3", "reason": "reason 3", "not": "interesting"},
                    ],
                },
            },
        )
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
            substrate_event_handler._fault_proposals(block)

        self.assertModelsEqual(models.Proposal.objects.order_by("id"), expected_proposals)

    @patch("core.event_handler.SubstrateEventHandler._create_accounts")
    @patch("core.event_handler.SubstrateEventHandler._create_daos")
    @patch("core.event_handler.SubstrateEventHandler._transfer_dao_ownerships")
    @patch("core.event_handler.SubstrateEventHandler._delete_daos")
    @patch("core.event_handler.SubstrateEventHandler._create_assets")
    @patch("core.event_handler.SubstrateEventHandler._transfer_assets")
    @patch("core.event_handler.SubstrateEventHandler._set_dao_metadata")
    @patch("core.event_handler.SubstrateEventHandler._dao_set_governances")
    @patch("core.event_handler.SubstrateEventHandler._create_proposals")
    @patch("core.event_handler.SubstrateEventHandler._register_votes")
    @patch("core.event_handler.SubstrateEventHandler._finalize_proposals")
    @patch("core.event_handler.SubstrateEventHandler._fault_proposals")
    def test_execute_actions(self, *mocks):
        event_handler = SubstrateEventHandler()
        block = models.Block.objects.create(hash="hash 0", number=0)

        with self.assertNumQueries(3):
            event_handler.execute_actions(block)

        block.refresh_from_db()
        self.assertTrue(block.executed)
        for mock in mocks:
            mock.assert_called_once_with(block=block)

        block_number, block_hash = cache.get("current_block")
        self.assertEqual(block_number, 0)
        self.assertEqual(block_hash, "hash 0")

    @patch("core.event_handler.logger")
    @patch("core.event_handler.SubstrateEventHandler._transfer_assets")
    def test_execute_actions_db_error(self, action_mock, logger_mock):
        event_handler = SubstrateEventHandler()
        block = models.Block.objects.create(hash="hash 0", number=0)
        action_mock.side_effect = IntegrityError

        with self.assertNumQueries(3), self.assertRaises(ParseBlockException):
            event_handler.execute_actions(block)

        block.refresh_from_db()
        self.assertFalse(block.executed)
        action_mock.assert_called_once_with(block=block)
        logger_mock.exception.assert_called_once_with("Database error while parsing Block #0.")

    @patch("core.event_handler.logger")
    @patch("core.event_handler.SubstrateEventHandler._dao_set_governances")
    def test_execute_actions_expected_error(self, action_mock, logger_mock):
        event_handler = SubstrateEventHandler()
        block = models.Block.objects.create(hash="hash 0", number=0)
        action_mock.side_effect = Exception

        with self.assertNumQueries(3), self.assertRaises(ParseBlockException):
            event_handler.execute_actions(block)

        block.refresh_from_db()
        self.assertFalse(block.executed)
        action_mock.assert_called_once_with(block=block)
        logger_mock.exception.assert_called_once_with("Unexpected error while parsing Block #0.")
