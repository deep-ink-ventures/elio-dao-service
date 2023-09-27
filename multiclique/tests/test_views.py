import base64
from collections.abc import Collection
from unittest.mock import ANY, patch

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
        self.sig1 = models.MultiCliqueSignatory.objects.create(public_key="pk1", name="sig1")
        self.sig2 = models.MultiCliqueSignatory.objects.create(public_key="pk2", name="sig2")
        self.sig3 = models.MultiCliqueSignatory.objects.create(public_key="pk3", name="sig3")
        self.sig4 = models.MultiCliqueSignatory.objects.create(public_key="pk4", name="sig4")
        self.pol1 = models.MultiCliquePolicy.objects.create(name="POL1", active=True)
        self.pol2 = models.MultiCliquePolicy.objects.create(name="POL2", active=False)
        self.mc1 = models.MultiCliqueAccount(address="addr1", name="acc1", policy=self.pol1, default_threshold=2)
        self.mc1.signatories.set([self.sig1, self.sig2, self.sig3, self.sig4])
        self.mc1.save()
        self.mc2 = models.MultiCliqueAccount(address="addr2", name="acc2", policy=self.pol2, default_threshold=2)
        self.mc2.signatories.set([self.sig2, self.sig3])
        self.mc2.save()
        self.txn1 = models.MultiCliqueTransaction.objects.create(
            multiclique_account=self.mc1,
            xdr="xdr1",
            preimage_hash="hash1",
            call_func="func1",
            call_args=["arg1"],
            approvers=["addr1"],
            status=models.TransactionStatus.EXECUTED,
            executed_at=now(),
        )
        self.txn2 = models.MultiCliqueTransaction.objects.create(
            multiclique_account=self.mc2,
            xdr="xdr2",
            preimage_hash="hash2",
            call_func="func2",
            call_args=["arg2"],
            approvers=["addr2"],
            status=models.TransactionStatus.EXECUTABLE,
            executed_at=now(),
        )

    @staticmethod
    def wrap_in_pagination_res(results: Collection) -> dict:
        return {"count": len(results), "next": None, "previous": None, "results": results}

    @staticmethod
    def fmt_dt(value):
        return DateTimeField().to_representation(value=value)

    def test_multiclique_account_get(self):
        expected_res = {
            "address": "addr1",
            "name": "acc1",
            "policy": "POL1",
            "signatories": [
                {"public_key": "pk1", "name": "sig1"},
                {"public_key": "pk2", "name": "sig2"},
                {"public_key": "pk3", "name": "sig3"},
                {"public_key": "pk4", "name": "sig4"},
            ],
            "default_threshold": 2,
        }

        with self.assertNumQueries(2):
            res = self.client.get(reverse("multiclique-accounts-detail", kwargs={"address": "addr1"}))

        self.assertEqual(res.status_code, HTTP_200_OK, res.json())
        self.assertDictEqual(res.json(), expected_res)

    def test_multiclique_account_list(self):
        expected_res = self.wrap_in_pagination_res(
            [
                {
                    "address": "addr1",
                    "name": "acc1",
                    "policy": "POL1",
                    "signatories": [
                        {"public_key": "pk1", "name": "sig1"},
                        {"public_key": "pk2", "name": "sig2"},
                        {"public_key": "pk3", "name": "sig3"},
                        {"public_key": "pk4", "name": "sig4"},
                    ],
                    "default_threshold": 2,
                },
                {
                    "address": "addr2",
                    "name": "acc2",
                    "policy": "POL2",
                    "signatories": [
                        {"public_key": "pk2", "name": "sig2"},
                        {"public_key": "pk3", "name": "sig3"},
                    ],
                    "default_threshold": 2,
                },
            ]
        )
        with self.assertNumQueries(3):
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
        mc3.signatories.set([self.sig1])
        mc3.save()
        mc4 = models.MultiCliqueAccount(address="addr4", name="acc4", policy=self.pol1, default_threshold=2)
        mc4.signatories.set([self.sig4, self.sig1])
        mc4.save()

        with self.assertNumQueries(3):
            res = self.client.get(reverse("multiclique-accounts-list"), {"signatories": _filter, "ordering": "address"})

        self.assertEqual(res.status_code, HTTP_200_OK, res.json())
        self.assertListEqual([entry["address"] for entry in res.json()["results"]], expected_res)

    def test_multiclique_account_create(self):
        expected_res = {
            "address": "addr3",
            "name": "acc1",
            "policy": "POL_3",
            "signatories": [
                {"public_key": "pk1", "name": "sig1"},
                {"public_key": "pk2", "name": "sig2"},
                {"public_key": "pk5", "name": None},  # new
                {"public_key": "pk6", "name": "sig6"},  # new
            ],
            "default_threshold": 3,
        }

        with self.assertNumQueries(17):
            res = self.client.post(
                reverse("multiclique-accounts-list"),
                data={
                    "address": "addr3",
                    "name": "acc1",
                    "policy": "pOl_ 3",
                    "signatories": [
                        {"public_key": "pk1", "name": "sig1"},
                        {"public_key": "pk2"},
                        {"public_key": "pk5"},
                        {"public_key": "pk6", "name": "sig6"},
                    ],
                    "default_threshold": 3,
                },
                content_type="application/json",
            )

        self.assertEqual(res.status_code, HTTP_201_CREATED, res.json())
        self.assertDictEqual(res.json(), expected_res)
        mc3 = models.MultiCliqueAccount.objects.get(address="addr3")
        self.assertModelEqual(
            mc3,
            models.MultiCliqueAccount(
                **{
                    "address": "addr3",
                    "name": "acc1",
                    "policy": models.MultiCliquePolicy.objects.get(name="POL_3"),
                    "default_threshold": 3,
                }
            ),
            ignore_fields=("created_at", "updated_at", "signatories"),
        )
        self.assertModelsEqual(
            mc3.signatories.all(),
            [
                self.sig1,
                self.sig2,
                models.MultiCliqueSignatory.objects.get(public_key="pk5"),
                models.MultiCliqueSignatory.objects.get(public_key="pk6"),
            ],
        )
        self.assertModelsEqual(
            models.MultiCliqueAccount.objects.order_by("address"),
            [self.mc1, self.mc2, mc3],
        )
        expected_sigs = [
            self.sig1,
            self.sig2,
            self.sig3,
            self.sig4,
            models.MultiCliqueSignatory(public_key="pk5"),
            models.MultiCliqueSignatory(public_key="pk6", name="sig6"),
        ]
        self.assertModelsEqual(models.MultiCliqueSignatory.objects.order_by("public_key"), expected_sigs)

    def test_multiclique_account_create_existing_account(self):
        expected_res = {
            "address": "addr3",
            "name": "acc1",
            "policy": "POL_3",
            "signatories": [
                {"public_key": "pk1", "name": "sig1"},
                {"public_key": "pk2", "name": "sig2"},
                {"public_key": "pk3", "name": "sig3"},
                {"public_key": "pk4", "name": "sig4"},
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
        mc3.signatories.set([self.sig1, self.sig2, self.sig3, self.sig4])
        mc3.save()

        with self.assertNumQueries(14):
            res = self.client.post(
                reverse("multiclique-accounts-list"),
                data={
                    "address": "addr3",
                    "name": "acc1",
                    "policy": "pOl_ 3",
                    "signatories": [
                        {"public_key": "pk1", "name": "sig1"},
                        {"public_key": "pk2", "name": "sig2"},
                        {"public_key": "pk3", "name": "sig3"},
                        {"public_key": "pk4", "name": "sig4"},
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
                    "policy": models.MultiCliquePolicy.objects.get(name="POL_3"),
                    "default_threshold": 3,
                }
            ),
            ignore_fields=("created_at", "updated_at", "signatories"),
        )
        self.assertModelsEqual(mc3.signatories.all(), [self.sig1, self.sig2, self.sig3, self.sig4])
        self.assertModelsEqual(models.MultiCliqueAccount.objects.order_by("address"), [self.mc1, self.mc2, mc3])

    def test_multiclique_account_create_existing_policy(self):
        expected_res = {
            "address": "addr2",
            "name": "acc1",
            "policy": "POL2",
            "signatories": [
                {"public_key": "pk1", "name": "sig1"},
                {"public_key": "pk2", "name": "sig2"},
                {"public_key": "pk3", "name": "sig3"},
                {"public_key": "pk4", "name": "sig4"},
            ],
            "default_threshold": 3,
        }

        with self.assertNumQueries(12):
            res = self.client.post(
                reverse("multiclique-accounts-list"),
                data={
                    "address": "addr2",
                    "name": "acc1",
                    "policy": "POL2",
                    "signatories": [
                        {"public_key": "pk1", "name": "sig1"},
                        {"public_key": "pk2", "name": "sig2"},
                        {"public_key": "pk3", "name": "sig3"},
                        {"public_key": "pk4", "name": "sig4"},
                    ],
                    "default_threshold": 3,
                },
                content_type="application/json",
            )

        self.assertEqual(res.status_code, HTTP_200_OK, res.json())
        self.assertDictEqual(res.json(), expected_res)

    def test_multiclique_account_create_invalid(self):
        expected_res = {
            "name": ["This field is required."],
        }

        with self.assertNumQueries(0):
            res = self.client.post(
                reverse("multiclique-accounts-list"),
                data={
                    "address": "addr2",
                    "policy": "POL2",
                    "signatories": [
                        {"public_key": "pk1", "name": "sig1"},
                        {"public_key": "pk2", "name": "sig2"},
                        {"public_key": "pk3", "name": "sig3"},
                        {"public_key": "pk4", "name": "sig4"},
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

        with self.assertNumQueries(2):
            res = self.client.get(reverse("multiclique-accounts-challenge", kwargs={"address": self.mc1.address}))

        self.assertEqual(res.status_code, HTTP_200_OK, res.json())
        self.assertDictEqual(res.json(), expected_res)
        self.assertEqual(cache.get(self.mc1.address), res.json()["challenge"])

    def test_multiclique_account_create_jwt_token(self):
        challenge = "hard_challenge"
        keypair = Keypair.random()
        cache.set(key=keypair.public_key, value=challenge, timeout=5)
        sig = base64.b64encode(keypair.sign(data=challenge.encode())).decode()
        acc = models.MultiCliqueAccount.objects.create(
            address=keypair.public_key, name="acc3", policy=self.pol1, default_threshold=2
        )

        with self.assertNumQueries(1):
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

        with self.assertNumQueries(1):
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
            "xdr": self.txn1.xdr,
            "preimage_hash": self.txn1.preimage_hash,
            "call_func": self.txn1.call_func,
            "call_args": self.txn1.call_args,
            "approvers": self.txn1.approvers,
            "rejecters": self.txn1.rejecters,
            "status": self.txn1.status,
            "executed_at": self.fmt_dt(self.txn1.executed_at),
            "created_at": self.fmt_dt(self.txn1.created_at),
            "updated_at": self.fmt_dt(self.txn1.updated_at),
            "multiclique_address": self.mc1.address,
            "default_threshold": self.mc1.default_threshold,
            "signatories": [
                {"public_key": "pk1", "name": "sig1"},
                {"public_key": "pk2", "name": "sig2"},
                {"public_key": "pk3", "name": "sig3"},
                {"public_key": "pk4", "name": "sig4"},
            ],
        }

        with self.assertNumQueries(2):
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
                    "xdr": self.txn1.xdr,
                    "preimage_hash": self.txn1.preimage_hash,
                    "call_func": self.txn1.call_func,
                    "call_args": self.txn1.call_args,
                    "approvers": self.txn1.approvers,
                    "rejecters": self.txn1.rejecters,
                    "status": self.txn1.status,
                    "executed_at": self.fmt_dt(self.txn1.executed_at),
                    "created_at": self.fmt_dt(self.txn1.created_at),
                    "updated_at": self.fmt_dt(self.txn1.updated_at),
                    "multiclique_address": self.mc1.address,
                    "default_threshold": self.mc1.default_threshold,
                    "signatories": [
                        {"public_key": "pk1", "name": "sig1"},
                        {"public_key": "pk2", "name": "sig2"},
                        {"public_key": "pk3", "name": "sig3"},
                        {"public_key": "pk4", "name": "sig4"},
                    ],
                },
                {
                    "xdr": self.txn2.xdr,
                    "preimage_hash": self.txn2.preimage_hash,
                    "call_func": self.txn2.call_func,
                    "call_args": self.txn2.call_args,
                    "approvers": self.txn2.approvers,
                    "rejecters": self.txn2.rejecters,
                    "status": self.txn2.status,
                    "executed_at": self.fmt_dt(self.txn2.executed_at),
                    "created_at": self.fmt_dt(self.txn2.created_at),
                    "updated_at": self.fmt_dt(self.txn2.updated_at),
                    "multiclique_address": self.mc1.address,
                    "default_threshold": self.mc1.default_threshold,
                    "signatories": [
                        {"public_key": "pk1", "name": "sig1"},
                        {"public_key": "pk2", "name": "sig2"},
                        {"public_key": "pk3", "name": "sig3"},
                        {"public_key": "pk4", "name": "sig4"},
                    ],
                },
            ]
        )

        with self.assertNumQueries(4):
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
                    "xdr": self.txn1.xdr,
                    "preimage_hash": self.txn1.preimage_hash,
                    "call_func": self.txn1.call_func,
                    "call_args": self.txn1.call_args,
                    "approvers": self.txn1.approvers,
                    "rejecters": self.txn1.rejecters,
                    "status": self.txn1.status,
                    "executed_at": self.fmt_dt(self.txn1.executed_at),
                    "created_at": self.fmt_dt(self.txn1.created_at),
                    "updated_at": self.fmt_dt(self.txn1.updated_at),
                    "multiclique_address": self.mc1.address,
                    "default_threshold": self.mc1.default_threshold,
                    "signatories": [
                        {"public_key": "pk1", "name": "sig1"},
                        {"public_key": "pk2", "name": "sig2"},
                        {"public_key": "pk3", "name": "sig3"},
                        {"public_key": "pk4", "name": "sig4"},
                    ],
                },
            ]
        )

        with self.assertNumQueries(3):
            res = self.client.get(
                reverse("multiclique-transactions-list"),
                HTTP_AUTHORIZATION=f"Bearer {str(RefreshToken.for_user(self.mc1).access_token)}",  # type: ignore
            )

        self.assertEqual(res.status_code, HTTP_200_OK, res.json())
        self.assertDictEqual(res.json(), expected_res)

    @patch("core.soroban.soroban_service.analyze_xdr")
    def test_multiclique_transaction_create(self, analyze_xdr_mock):
        analyze_xdr_mock.return_value = {
            "source_acc": "source_acc",
            "contract_address": "contract_addr",
            "func_name": "call_func3",
            "func_args": ["call_arg3"],
            "signers": ["addr1", "addr3"],
            "preimage_hash": "hash3",
        }
        expected_res = {
            "xdr": "xdr3",
            "preimage_hash": "hash3",
            "call_func": "call_func3",
            "call_args": ["call_arg3"],
            "approvers": ["addr1", "addr3"],
            "rejecters": [],
            "status": models.TransactionStatus.EXECUTABLE,
            "executed_at": None,
            "multiclique_address": self.mc1.address,
            "default_threshold": self.mc1.default_threshold,
            "signatories": [
                {"public_key": "pk1", "name": "sig1"},
                {"public_key": "pk2", "name": "sig2"},
                {"public_key": "pk3", "name": "sig3"},
                {"public_key": "pk4", "name": "sig4"},
            ],
        }

        with self.assertNumQueries(3):
            res = self.client.post(
                reverse("multiclique-transactions-list"),
                data={
                    "xdr": "xdr3",
                    "multiclique_address": self.mc1.address,
                },
                content_type="application/json",
                HTTP_AUTHORIZATION=f"Bearer {str(RefreshToken.for_user(self.mc1).access_token)}",  # type: ignore
            )

        self.assertEqual(res.status_code, HTTP_201_CREATED, res.json())
        txn = models.MultiCliqueTransaction.objects.get(xdr="xdr3")
        expected_res.update({"updated_at": self.fmt_dt(txn.updated_at), "created_at": self.fmt_dt(txn.created_at)})
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
                        "approvers": ["addr1", "addr3"],
                        "rejecters": [],
                        "status": models.TransactionStatus.EXECUTABLE,
                        "executed_at": None,
                        "multiclique_account": self.mc1,
                    }
                ),
            ],
            ignore_fields=("id", "created_at", "updated_at"),
        )

    @patch("core.soroban.soroban_service.analyze_xdr")
    def test_multiclique_transaction_create_invalid_xdr(self, analyze_xdr_mock):
        analyze_xdr_mock.side_effect = InvalidXDRException(ctx={"some": "ctx"})
        expected_res = {"error": "The XDR is invalid.", "ctx": {"some": "ctx"}}

        with self.assertNumQueries(0):
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

    @patch("core.soroban.soroban_service.analyze_xdr")
    def test_multiclique_transaction_create_missing_multiclique_acc(self, _mock):
        expected_res = {"error": "MultiCliqueAccount does not exist."}

        with self.assertNumQueries(1):
            res = self.client.post(
                reverse("multiclique-transactions-list"),
                data={
                    "xdr": "xdr3",
                    "multiclique_address": "wrong addr",
                },
                content_type="application/json",
                HTTP_AUTHORIZATION=f"Bearer {str(RefreshToken.for_user(self.mc1).access_token)}",  # type: ignore
            )

        self.assertEqual(res.status_code, HTTP_400_BAD_REQUEST, res.json())
        self.assertDictEqual(res.json(), expected_res)
        self.assertModelsEqual(models.MultiCliqueTransaction.objects.all(), [self.txn1, self.txn2])
