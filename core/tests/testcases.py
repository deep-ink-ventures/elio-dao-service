from collections.abc import Collection, Iterable
from typing import Sequence
from unittest.mock import Mock

from django import test
from django.core.cache import cache
from django.db.models import Model


class TestCaseBase(test.TestCase):
    def tearDown(self):  # noqa
        cache.clear()

    def assertExactCalls(self, mock: Mock, calls: Sequence):
        mock.assert_has_calls(calls=calls)
        self.assertEqual(len(calls), mock.call_count)


@test.tag("integration")
class IntegrationTestCase(TestCaseBase):
    databases = [
        "default",
    ]
    maxDiff = None

    def assertModelEqual(self, obj_1: Model, obj_2: Model, ignore_fields: Iterable = ("created_at", "updated_at")):
        """
        Args:
            obj_1: model instance 1
            obj_2: model instance 2
            ignore_fields: fields to ignore during comparison

        Raises:
            self.failureException

        compares both models' defined fields except those specified in 'ignore_fields'
        """
        self.assertIsInstance(obj_1, Model, "First argument is not a model instance")
        self.assertIsInstance(obj_2, Model, "First argument is not a model instance")
        self.assertEqual(type(obj_1), type(obj_2), "Arguments don't have the same type")
        for field in obj_1._meta.fields:
            name = field.attname
            if name in ignore_fields:
                continue
            val_1 = getattr(obj_1, name)
            val_2 = getattr(obj_2, name)
            if val_1 != val_2:
                self.fail(f"{obj_1} != {obj_2}:\n\t{name}: {val_1} != {val_2}")

    def assertModelsEqual(
        self,
        col_1: Collection[Model],
        col_2: Collection[Model],
        ignore_fields: Iterable[str] = ("created_at", "updated_at"),
    ):
        """
        Args:
            col_1: sorted! collection of Model instances
            col_2: sorted! collection of Model instances
            ignore_fields: fields to ignore during comparison

        Raises:
            self.failureException

        compares each iterable's models' defined fields except those specified in 'ignore_fields'
        """
        self.assertEqual(len(col_1), len(col_2), "length not equal")
        for obj_1, obj_2 in zip(col_1, col_2):
            self.assertModelEqual(obj_1, obj_2, ignore_fields)


@test.tag("unit")
class UnitTestCase(TestCaseBase, test.SimpleTestCase):
    maxDiff = None
