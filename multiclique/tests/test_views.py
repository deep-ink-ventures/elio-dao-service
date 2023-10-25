import base64
from collections.abc import Collection
from unittest.mock import ANY, Mock, patch

from ddt import data, ddt
from django.core.cache import cache
from django.urls import reverse
from django.utils.timezone import now
from rest_framework.fields import DateTimeField
from rest_framework.status import (
    HTTP_200_OK,
    HTTP_201_CREATED,
    HTTP_400_BAD_REQUEST,
    HTTP_401_UNAUTHORIZED,
    HTTP_404_NOT_FOUND,
)
from rest_framework_simplejwt.tokens import RefreshToken
from stellar_sdk import Keypair

from core.soroban import InvalidXDRException
from core.tests.testcases import IntegrationTestCase
from multiclique import models


@ddt
class MultiCliqueViewSetTest(IntegrationTestCase):
    def setUp(self):
        super().setUp()
        cache.clear()
        self.signer1 = models.MultiCliqueSignatory.objects.create(address="pk1", name="signer1")
        self.signer2 = models.MultiCliqueSignatory.objects.create(address="pk2", name="signer2")
        self.signer3 = models.MultiCliqueSignatory.objects.create(address="pk3", name="signer3")
        self.signer4 = models.MultiCliqueSignatory.objects.create(address="pk4", name="signer4")
        self.sig1 = models.MultiCliqueSignature.objects.create(signatory=self.signer1, signature="sig1")
        self.sig2 = models.MultiCliqueSignature.objects.create(signatory=self.signer2, signature="sig2")
        self.sig3 = models.MultiCliqueSignature.objects.create(signatory=self.signer3, signature="sig3")
        self.sig4 = models.MultiCliqueSignature.objects.create(signatory=self.signer4, signature="sig4")
        self.pol1 = models.MultiCliquePolicy.objects.create(address="POL1", name="ELIO_DAO")
        self.pol2 = models.MultiCliquePolicy.objects.create(address="POL2", name="ELIO_DAO")
        self.ctr1 = models.MultiCliqueContract.objects.create(
            address="CTR1", type=models.MultiCliqueContractType.ELIO_CORE, limit=10, already_spent=5
        )
        self.ctr1.policies.add(self.pol1)
        self.mc1 = models.MultiCliqueAccount(address="addr1", name="acc1", policy=self.pol1, default_threshold=2)
        self.mc1.signatories.set([self.signer1, self.signer2, self.signer3, self.signer4])
        self.mc1.save()
        self.mc2 = models.MultiCliqueAccount(address="addr2", name="acc2", policy=self.pol2, default_threshold=2)
        self.mc2.signatories.set([self.signer2, self.signer3])
        self.mc2.save()
        self.txn1 = models.MultiCliqueTransaction.objects.create(
            multiclique_account=self.mc1,
            xdr="xdr1",
            preimage_hash="hash1",
            call_func="func1",
            call_args=["arg1"],
            nonce=1,
            ledger=1,
            status=models.TransactionStatus.PENDING,
        )
        self.txn1.approvals.set([self.sig1])
        self.txn1.rejections.set([self.sig2, self.sig3])
        self.txn1.save()
        self.txn2 = models.MultiCliqueTransaction.objects.create(
            multiclique_account=self.mc2,
            xdr="xdr2",
            preimage_hash="hash2",
            call_func="func2",
            call_args=["arg2"],
            nonce=2,
            ledger=2,
            status=models.TransactionStatus.EXECUTABLE,
            executed_at=now(),
        )
        self.txn2.approvals.set([self.sig2, self.sig4])
        self.txn2.save()

    @staticmethod
    def wrap_in_pagination_res(results: Collection) -> dict:
        return {"count": len(results), "next": None, "previous": None, "results": results}

    @staticmethod
    def fmt_dt(value):
        return DateTimeField().to_representation(value=value)

    @patch("core.soroban.soroban_service.create_install_contract_transaction")
    def test_create_multiclique_contract_xdr(self, create_install_contract_transaction_mock):
        envelope = Mock()
        envelope.to_xdr.return_value = "xdr"
        create_install_contract_transaction_mock.return_value = envelope

        with self.assertNumQueries(0):
            res = self.client.post(
                reverse("multiclique-contracts-create-multiclique-contract-xdr"),
                data={"source_account_address": "addr1"},
                content_type="application/json",
            )

        self.assertEqual(res.status_code, HTTP_201_CREATED, res.json())
        self.assertDictEqual(res.json(), {"xdr": "xdr"})
        create_install_contract_transaction_mock.assert_called_once_with(
            source_account_address="addr1",
            wasm_id="some_multiclique_wasm_hash",
        )

    @patch("core.soroban.soroban_service.create_install_contract_transaction")
    def test_create_multiclique_contract_xdr_error(self, create_install_contract_transaction_mock):
        from core.soroban import SorobanException

        create_install_contract_transaction_mock.side_effect = SorobanException("roar")

        with self.assertNumQueries(0):
            res = self.client.post(
                reverse("multiclique-contracts-create-multiclique-contract-xdr"),
                data={"source_account_address": "addr1"},
                content_type="application/json",
            )

        self.assertEqual(res.status_code, HTTP_400_BAD_REQUEST, res.json())
        self.assertDictEqual(res.json(), {"error": "Unable to prepare transaction"})
        create_install_contract_transaction_mock.assert_called_once_with(
            source_account_address="addr1",
            wasm_id="some_multiclique_wasm_hash",
        )

    @patch("core.soroban.soroban_service.create_install_contract_transaction")
    def test_create_policy_contract_xdr(self, create_install_contract_transaction_mock):
        envelope = Mock()
        envelope.to_xdr.return_value = "xdr"
        create_install_contract_transaction_mock.return_value = envelope

        with self.assertNumQueries(0):
            res = self.client.post(
                reverse("multiclique-contracts-create-policy-contract-xdr"),
                data={"source_account_address": "addr1", "policy_preset": "ELIO_DAO"},
                content_type="application/json",
            )

        self.assertEqual(res.status_code, HTTP_201_CREATED, res.json())
        self.assertDictEqual(res.json(), {"xdr": "xdr"})
        create_install_contract_transaction_mock.assert_called_once_with(
            source_account_address="addr1",
            wasm_id="some_policy_wasm_hash",
        )

    @patch("core.soroban.soroban_service.create_install_contract_transaction")
    def test_create_policy_contract_xdr_invalid_policy_preset(self, create_install_contract_transaction_mock):
        with self.assertNumQueries(0):
            res = self.client.post(
                reverse("multiclique-contracts-create-policy-contract-xdr"),
                data={"source_account_address": "addr1", "policy_preset": "not elio"},
                content_type="application/json",
            )

        self.assertEqual(res.status_code, HTTP_400_BAD_REQUEST, res.json())
        self.assertDictEqual(res.json(), {"policy_preset": ['currently only "ELIO_DAO" is supported as policy preset']})
        create_install_contract_transaction_mock.assert_not_called()

    @patch("core.soroban.soroban_service.create_install_contract_transaction")
    def test_create_policy_contract_xdr_error(self, create_install_contract_transaction_mock):
        from core.soroban import SorobanException

        create_install_contract_transaction_mock.side_effect = SorobanException("roar")

        with self.assertNumQueries(0):
            res = self.client.post(
                reverse("multiclique-contracts-create-policy-contract-xdr"),
                data={"source_account_address": "addr1", "policy_preset": "ELIO_DAO"},
                content_type="application/json",
            )

        self.assertEqual(res.status_code, HTTP_400_BAD_REQUEST, res.json())
        self.assertDictEqual(res.json(), {"error": "Unable to prepare transaction"})
        create_install_contract_transaction_mock.assert_called_once_with(
            source_account_address="addr1",
            wasm_id="some_policy_wasm_hash",
        )

    def test_multiclique_account_get(self):
        expected_res = {
            "address": "addr1",
            "name": "acc1",
            "policy": {
                "address": "POL1",
                "name": "ELIO_DAO",
                "contracts": [
                    {
                        "address": "CTR1",
                        "already_spent": 5,
                        "limit": 10,
                        "type": models.MultiCliqueContractType.ELIO_CORE,
                    }
                ],
            },
            "signatories": [
                {"address": "pk1", "name": "signer1"},
                {"address": "pk2", "name": "signer2"},
                {"address": "pk3", "name": "signer3"},
                {"address": "pk4", "name": "signer4"},
            ],
            "default_threshold": 2,
        }

        with self.assertNumQueries(4):
            res = self.client.get(reverse("multiclique-accounts-detail", kwargs={"address": "addr1"}))

        self.assertEqual(res.status_code, HTTP_200_OK, res.json())
        self.assertDictEqual(res.json(), expected_res)

    def test_multiclique_account_list(self):
        expected_res = self.wrap_in_pagination_res(
            [
                {
                    "address": "addr1",
                    "name": "acc1",
                    "policy": {
                        "address": "POL1",
                        "name": "ELIO_DAO",
                        "contracts": [
                            {
                                "address": "CTR1",
                                "already_spent": 5,
                                "limit": 10,
                                "type": models.MultiCliqueContractType.ELIO_CORE,
                            }
                        ],
                    },
                    "signatories": [
                        {"address": "pk1", "name": "signer1"},
                        {"address": "pk2", "name": "signer2"},
                        {"address": "pk3", "name": "signer3"},
                        {"address": "pk4", "name": "signer4"},
                    ],
                    "default_threshold": 2,
                },
                {
                    "address": "addr2",
                    "name": "acc2",
                    "policy": {"address": "POL2", "name": "ELIO_DAO", "contracts": []},
                    "signatories": [
                        {"address": "pk2", "name": "signer2"},
                        {"address": "pk3", "name": "signer3"},
                    ],
                    "default_threshold": 2,
                },
            ]
        )
        with self.assertNumQueries(5):
            res = self.client.get(reverse("multiclique-accounts-list"), {"ordering": "address"})

        self.assertEqual(res.status_code, HTTP_200_OK, res.json())
        self.assertDictEqual(res.json(), expected_res)

    @data(
        # filter, expected_res
        ([], ["addr1", "addr2", "addr3", "addr4"]),
        ("pk1", ["addr1", "addr3", "addr4"]),
        ("pk2", ["addr1", "addr2"]),
        (["pk1"], ["addr1", "addr3", "addr4"]),
        (["pk1", "pk4"], ["addr1", "addr4"]),
    )
    def test_multiclique_account_list_filter(self, case):
        _filter, expected_res = case
        mc3 = models.MultiCliqueAccount(address="addr3", name="acc3", policy=self.pol1, default_threshold=2)
        mc3.signatories.set([self.signer1])
        mc3.save()
        mc4 = models.MultiCliqueAccount(address="addr4", name="acc4", policy=self.pol1, default_threshold=2)
        mc4.signatories.set([self.signer4, self.signer1])
        mc4.save()

        with self.assertNumQueries(5):
            res = self.client.get(reverse("multiclique-accounts-list"), {"signatories": _filter, "ordering": "address"})

        self.assertEqual(res.status_code, HTTP_200_OK, res.json())
        self.assertListEqual([entry["address"] for entry in res.json()["results"]], expected_res)

    @patch("core.soroban.SorobanService.set_trusted_contract_ids")
    def test_multiclique_account_create(self, set_trusted_contract_ids_mock):
        expected_res = {
            "address": "addr3",
            "name": "acc1",
            "policy": {"address": "POL3", "name": "ELIO_DAO", "contracts": []},
            "signatories": [
                {"address": "pk1", "name": "signer1"},
                {"address": "pk2", "name": "signer2"},
                {"address": "pk5", "name": None},  # new
                {"address": "pk6", "name": "signer6"},  # new
            ],
            "default_threshold": 3,
        }

        with self.assertNumQueries(18):
            res = self.client.post(
                reverse("multiclique-accounts-list"),
                data={
                    "address": "addr3",
                    "name": "acc1",
                    "policy": {"address": "POL3", "name": "ELIO_DAO"},
                    "signatories": [
                        {"address": "pk1", "name": "signer1"},
                        {"address": "pk2"},
                        {"address": "pk5"},
                        {"address": "pk6", "name": "signer6"},
                    ],
                    "default_threshold": 3,
                },
                content_type="application/json",
            )

        self.assertEqual(res.status_code, HTTP_200_OK, res.json())
        self.assertDictEqual(res.json(), expected_res)
        mc3 = models.MultiCliqueAccount.objects.get(address="addr3")
        self.assertModelEqual(
            mc3,
            models.MultiCliqueAccount(
                **{
                    "address": "addr3",
                    "name": "acc1",
                    "policy": models.MultiCliquePolicy.objects.get(address="POL3"),
                    "default_threshold": 3,
                }
            ),
            ignore_fields=("created_at", "updated_at", "signatories"),
        )
        self.assertModelsEqual(
            mc3.signatories.all(),
            [
                self.signer1,
                self.signer2,
                models.MultiCliqueSignatory.objects.get(address="pk5"),
                models.MultiCliqueSignatory.objects.get(address="pk6"),
            ],
        )
        self.assertModelsEqual(
            models.MultiCliqueAccount.objects.order_by("address"),
            [self.mc1, self.mc2, mc3],
        )
        expected_sigs = [
            self.signer1,
            self.signer2,
            self.signer3,
            self.signer4,
            models.MultiCliqueSignatory(address="pk5"),
            models.MultiCliqueSignatory(address="pk6", name="signer6"),
        ]
        self.assertModelsEqual(models.MultiCliqueSignatory.objects.order_by("address"), expected_sigs)
        set_trusted_contract_ids_mock.assert_called_once_with()

    @patch("core.soroban.SorobanService.set_trusted_contract_ids")
    def test_multiclique_account_create_existing_account(self, set_trusted_contract_ids_mock):
        expected_res = {
            "address": "addr3",
            "name": "acc1",
            "policy": {"address": "POL3", "name": "ELIO_DAO", "contracts": []},
            "signatories": [
                {"address": "pk1", "name": "signer1"},
                {"address": "pk2", "name": "signer2"},
                {"address": "pk3", "name": "signer3"},
                {"address": "pk4", "name": "signer4"},
            ],
            "default_threshold": 3,
        }
        mc3 = models.MultiCliqueAccount(
            **{
                "address": "addr3",
                "name": "acc2",
                "policy": self.pol1,
                "default_threshold": 2,
            }
        )
        mc3.signatories.set([self.signer1, self.signer2, self.signer3, self.signer4])
        mc3.save()

        with self.assertNumQueries(15):
            res = self.client.post(
                reverse("multiclique-accounts-list"),
                data={
                    "address": "addr3",
                    "name": "acc1",
                    "policy": {"address": "POL3", "name": "ELIO_DAO"},
                    "signatories": [
                        {"address": "pk1", "name": "signer1"},
                        {"address": "pk2", "name": "signer2"},
                        {"address": "pk3", "name": "signer3"},
                        {"address": "pk4", "name": "signer4"},
                    ],
                    "default_threshold": 3,
                },
                content_type="application/json",
            )

        self.assertEqual(res.status_code, HTTP_200_OK, res.json())
        self.assertDictEqual(res.json(), expected_res)
        mc3 = models.MultiCliqueAccount.objects.get(address="addr3")
        self.assertModelEqual(
            mc3,
            models.MultiCliqueAccount(
                **{
                    "address": "addr3",
                    "name": "acc1",
                    "policy": models.MultiCliquePolicy.objects.get(address="POL3"),
                    "default_threshold": 3,
                }
            ),
            ignore_fields=("created_at", "updated_at", "signatories"),
        )
        self.assertModelsEqual(mc3.signatories.all(), [self.signer1, self.signer2, self.signer3, self.signer4])
        self.assertModelsEqual(models.MultiCliqueAccount.objects.order_by("address"), [self.mc1, self.mc2, mc3])
        set_trusted_contract_ids_mock.assert_called_once_with()

    @patch("core.soroban.SorobanService.set_trusted_contract_ids")
    def test_multiclique_account_create_existing_policy(self, set_trusted_contract_ids_mock):
        expected_res = {
            "address": "addr2",
            "name": "acc1",
            "policy": {"address": "POL2", "name": "ELIO_DAO", "contracts": []},
            "signatories": [
                {"address": "pk1", "name": "signer1"},
                {"address": "pk2", "name": "signer2"},
                {"address": "pk3", "name": "signer3"},
                {"address": "pk4", "name": "signer4"},
            ],
            "default_threshold": 3,
        }

        with self.assertNumQueries(14):
            res = self.client.post(
                reverse("multiclique-accounts-list"),
                data={
                    "address": "addr2",
                    "name": "acc1",
                    "policy": {"address": "POL2", "name": "ELIO_DAO"},
                    "signatories": [
                        {"address": "pk1", "name": "signer1"},
                        {"address": "pk2", "name": "signer2"},
                        {"address": "pk3", "name": "signer3"},
                        {"address": "pk4", "name": "signer4"},
                    ],
                    "default_threshold": 3,
                },
                content_type="application/json",
            )

        self.assertEqual(res.status_code, HTTP_200_OK, res.json())
        self.assertDictEqual(res.json(), expected_res)
        set_trusted_contract_ids_mock.assert_called_once_with()

    def test_multiclique_account_create_invalid(self):
        expected_res = {"name": ["This field is required."]}

        with self.assertNumQueries(0):
            res = self.client.post(
                reverse("multiclique-accounts-list"),
                data={
                    "address": "addr2",
                    "policy": {"address": "POL3"},
                    "signatories": [
                        {"address": "pk1", "name": "signer1"},
                        {"address": "pk2", "name": "signer2"},
                        {"address": "pk3", "name": "signer3"},
                        {"address": "pk4", "name": "signer4"},
                    ],
                    "default_threshold": 3,
                },
                content_type="application/json",
            )

        self.assertEqual(res.status_code, HTTP_400_BAD_REQUEST, res.json())
        self.assertDictEqual(res.json(), expected_res)

    def test_multiclique_account_challenge(self):
        cache.clear()
        expected_res = {"challenge": ANY}

        with self.assertNumQueries(1):
            res = self.client.get(reverse("multiclique-accounts-challenge", kwargs={"address": self.mc1.address}))

        self.assertEqual(res.status_code, HTTP_200_OK, res.json())
        self.assertDictEqual(res.json(), expected_res)
        self.assertEqual(cache.get(self.mc1.address), res.json()["challenge"])

    def test_multiclique_account_create_jwt_token_acc(self):
        challenge = "hard_challenge"
        keypair = Keypair.random()
        cache.set(key=keypair.public_key, value=challenge, timeout=5)
        sig = base64.b64encode(keypair.sign(data=challenge.encode())).decode()
        acc = models.MultiCliqueAccount.objects.create(
            address=keypair.public_key, name="acc3", policy=self.pol1, default_threshold=2
        )

        with self.assertNumQueries(2):
            res = self.client.post(
                reverse("multiclique-accounts-create-jwt-token", kwargs={"address": acc.address}),
                data={"signature": sig},
                content_type="application/json",
            )

        self.assertEqual(res.status_code, HTTP_200_OK, res.json())
        self.assertDictEqual(res.json(), {"access": ANY, "refresh": ANY})

    def test_multiclique_account_create_jwt_token_signatory(self):
        acc = models.MultiCliqueAccount.objects.create(
            address="addr3", name="acc3", policy=self.pol1, default_threshold=2
        )
        challenge = "hard_challenge"
        keypair = Keypair.random()
        cache.set(key=acc.address, value=challenge, timeout=5)
        sig = base64.b64encode(keypair.sign(data=challenge.encode())).decode()
        acc.signatories.add(models.MultiCliqueSignatory.objects.create(address=keypair.public_key, name="som"))
        acc.save()

        with self.assertNumQueries(2):
            res = self.client.post(
                reverse("multiclique-accounts-create-jwt-token", kwargs={"address": acc.address}),
                data={"signature": sig},
                content_type="application/json",
            )

        self.assertEqual(res.status_code, HTTP_200_OK, res.json())
        self.assertDictEqual(res.json(), {"access": ANY, "refresh": ANY})

    def test_multiclique_account_create_jwt_token_wrong_sig(self):
        challenge = "hard_challenge"
        keypair = Keypair.random()
        cache.set(key=keypair.public_key, value=challenge, timeout=5)
        acc = models.MultiCliqueAccount.objects.create(
            address=keypair.public_key, name="acc3", policy=self.pol1, default_threshold=2
        )

        with self.assertNumQueries(2):
            res = self.client.post(
                reverse("multiclique-accounts-create-jwt-token", kwargs={"address": acc.address}),
                data={"signature": "wrong"},
                content_type="application/json",
            )

        self.assertEqual(res.status_code, HTTP_400_BAD_REQUEST, res.json())

    def test_multiclique_account_refresh_jwt_token(self):
        token = RefreshToken.for_user(self.mc1)  # type: ignore
        expected_res = {"access": ANY, "refresh": ANY}

        with self.assertNumQueries(0):
            res = self.client.post(
                reverse("multiclique-accounts-refresh-jwt-token", kwargs={"address": self.mc1.address}),
                data={"access": str(token.access_token), "refresh": str(token)},  # type: ignore
                content_type="application/json",
            )

        self.assertEqual(res.status_code, HTTP_200_OK, res.json())
        self.assertEqual(res.json(), expected_res)
        self.assertNotEqual(res.json()["access"], {"access": str(token.access_token)})  # type:ignore
        self.assertNotEqual(res.json()["refresh"], {"access": str(token)})

    def test_multiclique_transaction_get(self):
        expected_res = {
            "id": self.txn1.id,
            "xdr": self.txn1.xdr,
            "preimage_hash": self.txn1.preimage_hash,
            "call_func": self.txn1.call_func,
            "call_args": self.txn1.call_args,
            "approvals": [
                {"signature": "sig1", "signatory": {"address": "pk1", "name": "signer1"}},
            ],
            "rejections": [
                {"signature": "sig2", "signatory": {"address": "pk2", "name": "signer2"}},
                {"signature": "sig3", "signatory": {"address": "pk3", "name": "signer3"}},
            ],
            "status": self.txn1.status,
            "executed_at": self.fmt_dt(self.txn1.executed_at),
            "created_at": self.fmt_dt(self.txn1.created_at),
            "updated_at": self.fmt_dt(self.txn1.updated_at),
            "multiclique_address": self.mc1.address,
            "default_threshold": self.mc1.default_threshold,
            "signatories": [
                {"address": "pk1", "name": "signer1"},
                {"address": "pk2", "name": "signer2"},
                {"address": "pk3", "name": "signer3"},
                {"address": "pk4", "name": "signer4"},
            ],
        }

        with self.assertNumQueries(7):
            res = self.client.get(
                reverse("multiclique-transactions-detail", kwargs={"pk": self.txn1.id}),
                HTTP_AUTHORIZATION=f"Bearer {str(RefreshToken.for_user(self.mc1).access_token)}",  # type: ignore
            )

        self.assertEqual(res.status_code, HTTP_200_OK, res.json())
        self.assertDictEqual(res.json(), expected_res)

    def test_multiclique_transaction_get_filtering(self):
        expected_res = {"detail": "Not found."}

        with self.assertNumQueries(1):
            res = self.client.get(
                reverse("multiclique-transactions-detail", kwargs={"pk": self.txn1.id}),
                HTTP_AUTHORIZATION=f"Bearer {str(RefreshToken.for_user(self.mc2).access_token)}",  # type: ignore
            )

        self.assertEqual(res.status_code, HTTP_404_NOT_FOUND, res.json())
        self.assertDictEqual(res.json(), expected_res)

    def test_multiclique_transaction_get_no_auth(self):
        expected_res = {"detail": "Authentication credentials were not provided."}

        with self.assertNumQueries(0):
            res = self.client.get(
                reverse("multiclique-transactions-detail", kwargs={"pk": self.txn1.id}),
            )

        self.assertEqual(res.status_code, HTTP_401_UNAUTHORIZED, res.json())
        self.assertDictEqual(res.json(), expected_res)

    def test_multiclique_transaction_list(self):
        self.txn2.multiclique_account = self.mc1
        self.txn2.save()

        expected_res = self.wrap_in_pagination_res(
            [
                {
                    "id": self.txn1.id,
                    "xdr": self.txn1.xdr,
                    "preimage_hash": self.txn1.preimage_hash,
                    "call_func": self.txn1.call_func,
                    "call_args": self.txn1.call_args,
                    "approvals": [
                        {"signature": "sig1", "signatory": {"address": "pk1", "name": "signer1"}},
                    ],
                    "rejections": [
                        {"signature": "sig2", "signatory": {"address": "pk2", "name": "signer2"}},
                        {"signature": "sig3", "signatory": {"address": "pk3", "name": "signer3"}},
                    ],
                    "status": self.txn1.status,
                    "executed_at": self.fmt_dt(self.txn1.executed_at),
                    "created_at": self.fmt_dt(self.txn1.created_at),
                    "updated_at": self.fmt_dt(self.txn1.updated_at),
                    "multiclique_address": self.mc1.address,
                    "default_threshold": self.mc1.default_threshold,
                    "signatories": [
                        {"address": "pk1", "name": "signer1"},
                        {"address": "pk2", "name": "signer2"},
                        {"address": "pk3", "name": "signer3"},
                        {"address": "pk4", "name": "signer4"},
                    ],
                },
                {
                    "id": self.txn2.id,
                    "xdr": self.txn2.xdr,
                    "preimage_hash": self.txn2.preimage_hash,
                    "call_func": self.txn2.call_func,
                    "call_args": self.txn2.call_args,
                    "approvals": [
                        {"signature": "sig2", "signatory": {"address": "pk2", "name": "signer2"}},
                        {"signature": "sig4", "signatory": {"address": "pk4", "name": "signer4"}},
                    ],
                    "rejections": [],
                    "status": self.txn2.status,
                    "executed_at": self.fmt_dt(self.txn2.executed_at),
                    "created_at": self.fmt_dt(self.txn2.created_at),
                    "updated_at": self.fmt_dt(self.txn2.updated_at),
                    "multiclique_address": self.mc1.address,
                    "default_threshold": self.mc1.default_threshold,
                    "signatories": [
                        {"address": "pk1", "name": "signer1"},
                        {"address": "pk2", "name": "signer2"},
                        {"address": "pk3", "name": "signer3"},
                        {"address": "pk4", "name": "signer4"},
                    ],
                },
            ]
        )

        with self.assertNumQueries(8):
            res = self.client.get(
                reverse("multiclique-transactions-list"),
                HTTP_AUTHORIZATION=f"Bearer {str(RefreshToken.for_user(self.mc1).access_token)}",  # type: ignore
            )

        self.assertEqual(res.status_code, HTTP_200_OK, res.json())
        self.assertDictEqual(res.json(), expected_res)

    def test_multiclique_transaction_list_filtering(self):
        expected_res = self.wrap_in_pagination_res(
            [
                {
                    "id": self.txn1.id,
                    "xdr": self.txn1.xdr,
                    "preimage_hash": self.txn1.preimage_hash,
                    "call_func": self.txn1.call_func,
                    "call_args": self.txn1.call_args,
                    "approvals": [
                        {"signature": "sig1", "signatory": {"address": "pk1", "name": "signer1"}},
                    ],
                    "rejections": [
                        {"signature": "sig2", "signatory": {"address": "pk2", "name": "signer2"}},
                        {"signature": "sig3", "signatory": {"address": "pk3", "name": "signer3"}},
                    ],
                    "status": self.txn1.status,
                    "executed_at": self.fmt_dt(self.txn1.executed_at),
                    "created_at": self.fmt_dt(self.txn1.created_at),
                    "updated_at": self.fmt_dt(self.txn1.updated_at),
                    "multiclique_address": self.mc1.address,
                    "default_threshold": self.mc1.default_threshold,
                    "signatories": [
                        {"address": "pk1", "name": "signer1"},
                        {"address": "pk2", "name": "signer2"},
                        {"address": "pk3", "name": "signer3"},
                        {"address": "pk4", "name": "signer4"},
                    ],
                },
            ]
        )

        with self.assertNumQueries(8):
            res = self.client.get(
                reverse("multiclique-transactions-list"),
                HTTP_AUTHORIZATION=f"Bearer {str(RefreshToken.for_user(self.mc1).access_token)}",  # type: ignore
            )

        self.assertEqual(res.status_code, HTTP_200_OK, res.json())
        self.assertDictEqual(res.json(), expected_res)

    def test_multiclique_transaction_list_status_filter(self):
        expected_res = self.wrap_in_pagination_res(
            [
                {
                    "id": self.txn1.id,
                    "xdr": self.txn1.xdr,
                    "preimage_hash": self.txn1.preimage_hash,
                    "call_func": self.txn1.call_func,
                    "call_args": self.txn1.call_args,
                    "approvals": [
                        {"signature": "sig1", "signatory": {"address": "pk1", "name": "signer1"}},
                    ],
                    "rejections": [
                        {"signature": "sig2", "signatory": {"address": "pk2", "name": "signer2"}},
                        {"signature": "sig3", "signatory": {"address": "pk3", "name": "signer3"}},
                    ],
                    "status": self.txn1.status,
                    "executed_at": self.fmt_dt(self.txn1.executed_at),
                    "created_at": self.fmt_dt(self.txn1.created_at),
                    "updated_at": self.fmt_dt(self.txn1.updated_at),
                    "multiclique_address": self.mc1.address,
                    "default_threshold": self.mc1.default_threshold,
                    "signatories": [
                        {"address": "pk1", "name": "signer1"},
                        {"address": "pk2", "name": "signer2"},
                        {"address": "pk3", "name": "signer3"},
                        {"address": "pk4", "name": "signer4"},
                    ],
                },
            ]
        )

        with self.assertNumQueries(8):
            res = self.client.get(
                reverse("multiclique-transactions-list"),
                {"status": models.TransactionStatus.PENDING},
                HTTP_AUTHORIZATION=f"Bearer {str(RefreshToken.for_user(self.mc1).access_token)}",  # type: ignore
            )

        self.assertEqual(res.status_code, HTTP_200_OK, res.json())
        self.assertDictEqual(res.json(), expected_res)

        with self.assertNumQueries(1):
            res = self.client.get(
                reverse("multiclique-transactions-list"),
                {"status": models.TransactionStatus.EXECUTABLE},
                HTTP_AUTHORIZATION=f"Bearer {str(RefreshToken.for_user(self.mc1).access_token)}",  # type: ignore
            )

        self.assertEqual(res.status_code, HTTP_200_OK, res.json())
        self.assertDictEqual(res.json(), {"count": 0, "next": None, "previous": None, "results": []})

    @patch("core.soroban.soroban_service.analyze_transaction")
    def test_multiclique_transaction_create(self, analyze_transaction_mock):
        analyze_transaction_mock.return_value = {
            "source_acc": "source_acc",
            "contract_address": "contract_addr",
            "func_name": "call_func3",
            "func_args": ["call_arg3"],
            "preimage_hash": "hash3",
            "nonce": 3,
            "ledger": 3,
        }
        expected_res = {
            "xdr": "xdr3",
            "preimage_hash": "hash3",
            "call_func": "call_func3",
            "call_args": ["call_arg3"],
            "approvals": [],
            "rejections": [],
            "status": models.TransactionStatus.PENDING,
            "executed_at": None,
            "multiclique_address": self.mc1.address,
            "default_threshold": self.mc1.default_threshold,
            "signatories": [
                {"address": "pk1", "name": "signer1"},
                {"address": "pk2", "name": "signer2"},
                {"address": "pk3", "name": "signer3"},
                {"address": "pk4", "name": "signer4"},
            ],
        }

        with self.assertNumQueries(5):
            res = self.client.post(
                reverse("multiclique-transactions-list"),
                data={"xdr": "xdr3"},
                content_type="application/json",
                HTTP_AUTHORIZATION=f"Bearer {str(RefreshToken.for_user(self.mc1).access_token)}",  # type: ignore
            )

        self.assertEqual(res.status_code, HTTP_201_CREATED, res.json())
        txn = models.MultiCliqueTransaction.objects.get(xdr="xdr3")
        expected_res.update(
            {"id": txn.id, "updated_at": self.fmt_dt(txn.updated_at), "created_at": self.fmt_dt(txn.created_at)}
        )
        self.assertDictEqual(res.json(), expected_res)
        self.assertModelsEqual(
            models.MultiCliqueTransaction.objects.order_by("xdr"),
            [
                self.txn1,
                self.txn2,
                models.MultiCliqueTransaction(
                    **{
                        "xdr": "xdr3",
                        "preimage_hash": "hash3",
                        "call_func": "call_func3",
                        "call_args": ["call_arg3"],
                        "nonce": 3,
                        "ledger": 3,
                        "status": models.TransactionStatus.PENDING,
                        "executed_at": None,
                        "multiclique_account": self.mc1,
                    }
                ),
            ],
            ignore_fields=("id", "approvals", "rejections", "created_at", "updated_at"),
        )
        self.assertModelsEqual(list(txn.approvals.all()), [])
        self.assertListEqual(list(txn.rejections.all()), [])

    @patch("core.soroban.soroban_service.analyze_transaction")
    def test_multiclique_transaction_create_invalid_xdr(self, analyze_transaction_mock):
        analyze_transaction_mock.side_effect = InvalidXDRException(ctx={"some": "ctx"})
        expected_res = {"error": "The XDR is invalid.", "some": "ctx"}

        with self.assertNumQueries(1):
            res = self.client.post(
                reverse("multiclique-transactions-list"),
                data={
                    "xdr": "xdr3",
                    "multiclique_address": self.mc1.address,
                },
                content_type="application/json",
                HTTP_AUTHORIZATION=f"Bearer {str(RefreshToken.for_user(self.mc1).access_token)}",  # type: ignore
            )

        self.assertEqual(res.status_code, HTTP_400_BAD_REQUEST, res.json())
        self.assertDictEqual(res.json(), expected_res)
        self.assertModelsEqual(models.MultiCliqueTransaction.objects.all(), [self.txn1, self.txn2])

    @patch("core.soroban.soroban_service.authorize_transaction")
    @patch("core.soroban.soroban_service.prepare_transaction")
    @patch("core.soroban.soroban_service.create_signature_data")
    def test_multiclique_transaction_patch_executable(
        self, authorize_transaction_mock, prepare_transaction_mock, create_signature_data_mock
    ):
        envelope_1 = Mock()
        envelope_2 = Mock()
        envelope_2.to_xdr.return_value = "new_xdr"
        create_signature_data_mock.return_value = {"signature": "data"}
        authorize_transaction_mock.return_value = envelope_1
        prepare_transaction_mock.return_value = envelope_2
        expected_res = {
            "id": self.txn1.id,
            "xdr": "new_xdr",
            "preimage_hash": self.txn1.preimage_hash,
            "call_func": self.txn1.call_func,
            "call_args": self.txn1.call_args,
            "approvals": [
                {"signature": "sig1", "signatory": {"address": "pk1", "name": "signer1"}},
                {"signature": "sig3", "signatory": {"address": "pk3", "name": "signer3"}},
                {"signature": "sig4", "signatory": {"address": "pk4", "name": "signer4"}},
            ],
            "rejections": [
                {"signature": "sig2", "signatory": {"address": "pk2", "name": "signer2"}},
            ],
            "status": models.TransactionStatus.EXECUTABLE,
            "executed_at": self.fmt_dt(self.txn1.executed_at),
            "created_at": self.fmt_dt(self.txn1.created_at),
            "multiclique_address": self.mc1.address,
            "default_threshold": self.mc1.default_threshold,
            "signatories": [
                {"address": "pk1", "name": "signer1"},
                {"address": "pk2", "name": "signer2"},
                {"address": "pk3", "name": "signer3"},
                {"address": "pk4", "name": "signer4"},
            ],
        }

        with self.assertNumQueries(23):
            res = self.client.patch(
                reverse("multiclique-transactions-detail", kwargs={"pk": self.txn1.id}),
                data={
                    "approvals": [
                        {"signature": "sig3", "signatory": {"address": "pk3", "name": "signer3"}},
                        {"signature": "sig4", "signatory": {"address": "pk4", "name": "signer4"}},
                    ]
                },
                content_type="application/json",
                HTTP_AUTHORIZATION=f"Bearer {str(RefreshToken.for_user(self.mc1).access_token)}",  # type: ignore
            )

        self.assertEqual(res.status_code, HTTP_200_OK, res.json())
        self.txn1.refresh_from_db()
        expected_res.update({"updated_at": self.fmt_dt(self.txn1.updated_at)})
        self.assertDictEqual(res.json(), expected_res)
        self.assertModelsEqual(
            models.MultiCliqueTransaction.objects.order_by("xdr"),
            [
                models.MultiCliqueTransaction(
                    **{
                        "id": self.txn1.id,
                        "xdr": "new_xdr",
                        "preimage_hash": self.txn1.preimage_hash,
                        "call_func": self.txn1.call_func,
                        "call_args": self.txn1.call_args,
                        "nonce": self.txn1.nonce,
                        "ledger": self.txn1.ledger,
                        "updated_at": self.txn1.updated_at,
                        "created_at": self.txn1.created_at,
                        "status": models.TransactionStatus.EXECUTABLE,
                        "executed_at": None,
                        "multiclique_account": self.mc1,
                    }
                ),
                self.txn2,
            ],
            ignore_fields=("approvals", "rejections"),
        )
        self.assertModelsEqual(self.txn1.approvals.all(), [self.sig1, self.sig3, self.sig4])
        self.assertModelsEqual(self.txn1.rejections.all(), [self.sig2])

    @patch("core.soroban.soroban_service.authorize_transaction")
    @patch("core.soroban.soroban_service.prepare_transaction")
    @patch("core.soroban.soroban_service.create_signature_data")
    def test_multiclique_transaction_patch_rejected(
        self, authorize_transaction_mock, prepare_transaction_mock, create_signature_data_mock
    ):
        envelope_1 = Mock()
        envelope_2 = Mock()
        envelope_2.to_xdr.return_value = "new_xdr"
        create_signature_data_mock.return_value = {"signature": "data"}
        authorize_transaction_mock.return_value = envelope_1
        prepare_transaction_mock.return_value = envelope_2
        expected_res = {
            "id": self.txn1.id,
            "xdr": self.txn1.xdr,
            "preimage_hash": self.txn1.preimage_hash,
            "call_func": self.txn1.call_func,
            "call_args": self.txn1.call_args,
            "approvals": [
                {"signature": "sig2", "signatory": {"address": "pk2", "name": "signer2"}},
            ],
            "rejections": [
                {"signature": "sig1", "signatory": {"address": "pk1", "name": "signer1"}},
                {"signature": "sig3", "signatory": {"address": "pk3", "name": "signer3"}},
                {"signature": "sig4", "signatory": {"address": "pk4", "name": "signer4"}},
            ],
            "status": models.TransactionStatus.REJECTED,
            "executed_at": self.fmt_dt(self.txn1.executed_at),
            "created_at": self.fmt_dt(self.txn1.created_at),
            "multiclique_address": self.mc1.address,
            "default_threshold": self.mc1.default_threshold,
            "signatories": [
                {"address": "pk1", "name": "signer1"},
                {"address": "pk2", "name": "signer2"},
                {"address": "pk3", "name": "signer3"},
                {"address": "pk4", "name": "signer4"},
            ],
        }

        with self.assertNumQueries(27):
            res = self.client.patch(
                reverse("multiclique-transactions-detail", kwargs={"pk": self.txn1.id}),
                data={
                    "approvals": [
                        {"signature": "sig2", "signatory": {"address": "pk2", "name": "signer2"}},
                    ],
                    "rejections": [
                        {"signature": "sig1", "signatory": {"address": "pk1", "name": "signer1"}},
                        {"signature": "sig4", "signatory": {"address": "pk4", "name": "signer4"}},
                    ],
                },
                content_type="application/json",
                HTTP_AUTHORIZATION=f"Bearer {str(RefreshToken.for_user(self.mc1).access_token)}",  # type: ignore
            )

        self.assertEqual(res.status_code, HTTP_200_OK, res.json())
        self.txn1.refresh_from_db()
        expected_res.update({"updated_at": self.fmt_dt(self.txn1.updated_at)})
        self.assertDictEqual(res.json(), expected_res)
        self.assertModelsEqual(
            models.MultiCliqueTransaction.objects.order_by("xdr"),
            [
                models.MultiCliqueTransaction(
                    **{
                        "id": self.txn1.id,
                        "xdr": self.txn1.xdr,
                        "preimage_hash": self.txn1.preimage_hash,
                        "call_func": self.txn1.call_func,
                        "call_args": self.txn1.call_args,
                        "nonce": self.txn1.nonce,
                        "ledger": self.txn1.ledger,
                        "updated_at": self.txn1.updated_at,
                        "created_at": self.txn1.created_at,
                        "status": models.TransactionStatus.REJECTED,
                        "executed_at": None,
                        "multiclique_account": self.mc1,
                    }
                ),
                self.txn2,
            ],
            ignore_fields=("approvals", "rejections"),
        )
        self.assertModelsEqual(self.txn1.approvals.all(), [self.sig2])
        self.assertModelsEqual(self.txn1.rejections.all(), [self.sig1, self.sig3, self.sig4])
