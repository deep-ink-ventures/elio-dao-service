from collections.abc import Collection
from unittest.mock import patch

from django.urls import reverse
from django.utils.timezone import now
from rest_framework.fields import DateTimeField
from rest_framework.status import HTTP_200_OK, HTTP_201_CREATED, HTTP_400_BAD_REQUEST

from core.soroban import InvalidXDRException
from core.tests.testcases import IntegrationTestCase
from multiclique import models


class MultiCliqueViewSetTest(IntegrationTestCase):
    def setUp(self):
        super().setUp()
        self.public_keys = ["pk1", "pk2", "pk3", "pk4"]
        self.pol1 = models.MultiCliquePolicy.objects.create(name="POL1", active=True)
        self.pol2 = models.MultiCliquePolicy.objects.create(name="POL2", active=False)
        self.mc1 = models.MultiCliqueAccount.objects.create(
            address="addr1", policy=self.pol1, public_keys=self.public_keys, default_threshold=2
        )
        self.mc2 = models.MultiCliqueAccount.objects.create(
            address="addr2", policy=self.pol2, public_keys=self.public_keys[1:3], default_threshold=2
        )
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
            "policy": "POL1",
            "public_keys": self.public_keys,
            "default_threshold": 2,
        }
        with self.assertNumQueries(1):
            res = self.client.get(reverse("multiclique-accounts-detail", kwargs={"address": "addr1"}))

        self.assertEqual(res.status_code, HTTP_200_OK)
        self.assertDictEqual(res.json(), expected_res)

    def test_multiclique_account_list(self):
        expected_res = self.wrap_in_pagination_res(
            [
                {
                    "address": "addr1",
                    "policy": "POL1",
                    "public_keys": ["pk1", "pk2", "pk3", "pk4"],
                    "default_threshold": 2,
                },
                {
                    "address": "addr2",
                    "policy": "POL2",
                    "public_keys": ["pk2", "pk3"],
                    "default_threshold": 2,
                },
            ]
        )
        with self.assertNumQueries(2):
            res = self.client.get(reverse("multiclique-accounts-list"))

        self.assertEqual(res.status_code, HTTP_200_OK)
        self.assertDictEqual(res.json(), expected_res)

    def test_multiclique_account_create(self):
        expected_res = {
            "address": "addr3",
            "policy": "POL_3",
            "public_keys": self.public_keys,
            "default_threshold": 3,
        }
        with self.assertNumQueries(11):
            res = self.client.post(
                reverse("multiclique-accounts-list"),
                data={
                    "address": "addr3",
                    "policy": "pOl_ 3",
                    "public_keys": ["pk1", "pk2", "pk3", "pk4"],
                    "default_threshold": 3,
                },
                content_type="application/json",
            )

        self.assertEqual(res.status_code, HTTP_201_CREATED)
        self.assertDictEqual(res.json(), expected_res)
        self.assertModelsEqual(
            models.MultiCliqueAccount.objects.order_by("address"),
            [
                self.mc1,
                self.mc2,
                models.MultiCliqueAccount(
                    **{**expected_res, "policy": models.MultiCliquePolicy.objects.get(name="POL_3")}
                ),
            ],
        )

    def test_multiclique_account_create_existing_account(self):
        expected_res = {
            "address": "addr3",
            "policy": "POL_3",
            "public_keys": self.public_keys,
            "default_threshold": 3,
        }
        models.MultiCliqueAccount.objects.create(
            **{
                "address": "addr3",
                "policy": self.pol1,
                "public_keys": self.public_keys,
                "default_threshold": 2,
            }
        )
        with self.assertNumQueries(9):
            res = self.client.post(
                reverse("multiclique-accounts-list"),
                data={
                    "address": "addr3",
                    "policy": "pOl_ 3",
                    "public_keys": ["pk1", "pk2", "pk3", "pk4"],
                    "default_threshold": 3,
                },
                content_type="application/json",
            )

        self.assertEqual(res.status_code, HTTP_200_OK)
        self.assertDictEqual(res.json(), expected_res)
        self.assertModelsEqual(
            models.MultiCliqueAccount.objects.order_by("address"),
            [
                self.mc1,
                self.mc2,
                models.MultiCliqueAccount(
                    **{
                        "address": "addr3",
                        "policy": models.MultiCliquePolicy.objects.get(name="POL_3"),
                        "public_keys": self.public_keys,
                        "default_threshold": 3,
                    }
                ),
            ],
        )

    def test_multiclique_account_create_existing_policy(self):
        expected_res = {
            "address": "addr2",
            "policy": "POL2",
            "public_keys": self.public_keys,
            "default_threshold": 3,
        }
        with self.assertNumQueries(6):
            res = self.client.post(
                reverse("multiclique-accounts-list"),
                data={
                    "address": "addr2",
                    "policy": "POL2",
                    "public_keys": ["pk1", "pk2", "pk3", "pk4"],
                    "default_threshold": 3,
                },
                content_type="application/json",
            )

        self.assertEqual(res.status_code, HTTP_200_OK)
        self.assertDictEqual(res.json(), expected_res)

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
            "public_keys": self.mc1.public_keys,
        }
        with self.assertNumQueries(1):
            res = self.client.get(
                reverse("multiclique-transactions-detail", kwargs={"xdr": "xdr1"}),
            )

        self.assertEqual(res.status_code, HTTP_200_OK)
        self.assertDictEqual(res.json(), expected_res)

    def test_multiclique_transaction_list(self):
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
                    "public_keys": self.mc1.public_keys,
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
                    "multiclique_address": self.mc2.address,
                    "default_threshold": self.mc2.default_threshold,
                    "public_keys": self.mc2.public_keys,
                },
            ]
        )
        with self.assertNumQueries(2):
            res = self.client.get(
                reverse("multiclique-transactions-list"),
            )

        self.assertEqual(res.status_code, HTTP_200_OK)
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
            "public_keys": self.mc1.public_keys,
        }

        with self.assertNumQueries(2):
            res = self.client.post(
                reverse("multiclique-transactions-list"),
                data={
                    "xdr": "xdr3",
                    "multiclique_address": self.mc1.address,
                },
                content_type="application/json",
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
            )

        self.assertEqual(res.status_code, HTTP_400_BAD_REQUEST, res.json())
        self.assertDictEqual(res.json(), expected_res)
        self.assertModelsEqual(models.MultiCliqueTransaction.objects.all(), [self.txn1, self.txn2])
