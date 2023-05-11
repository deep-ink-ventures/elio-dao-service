from unittest.mock import Mock

from ddt import data, ddt
from django.core.exceptions import FieldError
from django.db import connection, models

from core.tests.testcases import IntegrationTestCase, UnitTestCase
from core.view_utils import FilterBackend, MultiQsLimitOffsetPagination, SearchableMixin


@ddt
class FilterBackendTest(UnitTestCase):
    def setUp(self) -> None:
        self.filter_backend = FilterBackend()

    @data(
        # query_params, allowed_filter_fields, allowed_order_fields, expected err msg
        # no allowed filter fields
        ({"a": 1}, (), (), "'a' is an invalid filter field. Choices are: id, pk"),
        # not in allowed filter fields
        ({"a": 1, "b": 1}, ("a",), (), "'b' is an invalid filter field. Choices are: id, pk"),
        ({"a": 1, "b": 1}, ("a",), ("a", "b"), "'b' is an invalid filter field. Choices are: id, pk"),
        # no allowed order fields
        ({"order_by": "a"}, (), (), "'a' is an invalid order field. Choices are: id, pk"),
        # not in allowed order fields
        ({"order_by": "a,b"}, (), ("a",), "'b' is an invalid order field. Choices are: id, pk, a"),
        ({"order_by": "a,b"}, ("a", "b"), ("a",), "'b' is an invalid order field. Choices are: id, pk, a"),
        # happy paths
        ({"id": 1}, (), (), None),
        ({"pk": 1}, (), (), None),
        ({"a": 1}, ("a",), (), None),
        ({"a": 1}, ("a", "b"), ("a", "b"), None),
        ({"a": 1, "b": 2}, ("a", "b"), (), None),
        ({"order_by": "id"}, (), (), None),
        ({"order_by": "pk"}, (), (), None),
        ({"order_by": "a"}, (), ("a",), None),
        ({"order_by": "a,b"}, (), ("a", "b"), None),
        ({"a": 1, "order_by": "b"}, ("a",), ("b",), None),
        ({"a": 1, "b": 2, "order_by": "c,d,-f,-id"}, ("a", "b"), ("c", "d", "f"), None),
    )
    def test_filter_queryset(self, case):
        query_params, allowed_filter_fields, allowed_order_fields, expected_err_msg = case
        request = Mock(query_params=query_params)
        qs = Mock()
        view = Mock(allowed_filter_fields=allowed_filter_fields, allowed_order_fields=allowed_order_fields)

        if expected_err_msg:
            with self.assertRaisesMessage(FieldError, expected_err_msg):
                self.assertIsNone(self.filter_backend.filter_queryset(request=request, queryset=qs, view=view))
        else:
            res = self.filter_backend.filter_queryset(request=request, queryset=qs, view=view)
            order_by = query_params.pop("order_by", [])

            if query_params:
                qs.filter.assert_called_once_with(**query_params)
                if not order_by:
                    self.assertEqual(res, qs.filter())
            else:
                qs.filter.assert_called_once_with()

            if order_by:
                qs.filter().order_by.assert_called_once_with(*order_by.split(","))
                self.assertEqual(res, qs.filter().order_by())


class TestModel(models.Model):
    pass


@ddt
class MultiQsLimitOffsetPaginationTest(IntegrationTestCase):
    def setUp(self):
        with connection.cursor() as cursor:
            cursor.execute("create table if not exists core_testmodel (id serial not null primary key);")
        self.paginator = MultiQsLimitOffsetPagination()
        TestModel.objects.bulk_create([TestModel(id=i) for i in range(1, 11)])

    def tearDown(self):
        with connection.cursor() as cursor:
            cursor.execute("drop table if exists core_testmodel;")

    @data(
        # addrs to filter by per qs, query_params, expected addr order of res, expected query count
        # 1 qs
        (((1, 2, 4, 7, 8, 9, 10),), {}, (1, 2, 4, 7, 8, 9, 10), 2),
        (((1, 2, 4, 7, 8, 9, 10),), {"limit": 2}, (1, 2), 2),
        (((1, 2, 4, 7, 8, 9, 10),), {"limit": 2, "offset": 5}, (9, 10), 2),
        (((1, 2, 4, 7, 8, 9, 10),), {"limit": 2, "offset": 6}, (10,), 2),
        # multi qs
        (((3,), (5, 6), (1, 2, 4, 7, 8, 9, 10)), {}, (3, 5, 6, 1, 2, 4, 7, 8, 9, 10), 6),
        (((3,), (5, 6), (1, 2, 4, 7, 8, 9, 10)), {"limit": 5}, (3, 5, 6, 1, 2), 6),
        (((3,), (5, 6), (1, 2, 4, 7, 8, 9, 10)), {"limit": 5, "offset": 2}, (6, 1, 2, 4, 7), 5),
        (((3,), (5, 6), (1, 2, 4, 7, 8, 9, 10)), {"limit": 3, "offset": 3}, (1, 2, 4), 4),
    )
    def test_paginate_querysets(self, case):
        qss_addrs, query_params, expected_order, expected_query_count = case
        qss = [TestModel.objects.filter(id__in=qs_addrs) for qs_addrs in qss_addrs]
        expected_res = [TestModel(id=expected_addr) for expected_addr in expected_order]

        # 1 count query per qs + 1 select query per used qs
        with self.assertNumQueries(expected_query_count):
            res = self.paginator.paginate_querysets(qss=qss, request=Mock(query_params=query_params))

        self.assertListEqual(res, expected_res)

    def test_paginate_queryset_no_limit(self):
        with self.assertNumQueries(0):
            self.paginator.default_limit = None
            self.assertIsNone(
                self.paginator.paginate_querysets(qss=[TestModel.objects.filter(id=1)], request=Mock(query_params={}))
            )


class SearchableMixinTest(UnitTestCase):
    @staticmethod
    def test_empty_view():
        # shouldn't raise
        SearchableMixin(nice_kwarg="idd")

    @staticmethod
    def test_no_allowed_fields():
        class _SearchableMixin(SearchableMixin):
            queryset = Mock()

            def retrieve(self, *args, **kwargs):
                pass

            def list(self, *args, **kwargs):
                pass

        # shouldn't raise
        _SearchableMixin(nice_kwarg="idd")
