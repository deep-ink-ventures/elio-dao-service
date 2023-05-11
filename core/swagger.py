from django.conf import settings
from drf_extra_fields.fields import Base64ImageField
from drf_yasg import openapi
from drf_yasg.inspectors import FieldInspector, NotHandled, PaginatorInspector
from rest_framework.pagination import (
    CursorPagination,
    LimitOffsetPagination,
    PageNumberPagination,
)


class Base64ImageFieldInspector(FieldInspector):
    def field_to_swagger_object(self, field, swagger_object_type, use_references, **kwargs):
        swagger_type, _ = self._get_partial_types(field, swagger_object_type, use_references, **kwargs)

        if isinstance(field, Base64ImageField) and swagger_object_type == openapi.Schema:
            return swagger_type(type=openapi.TYPE_STRING)

        return NotHandled


class PaginationInspector(PaginatorInspector):
    """
    improved DjangoRestResponsePagination
    - all properties are required
    - improved example
    """

    def get_paginated_response(self, paginator, response_schema):
        assert response_schema.type == openapi.TYPE_ARRAY, "array return expected for paged response"
        paged_schema = None
        if isinstance(paginator, (LimitOffsetPagination, PageNumberPagination, CursorPagination)):
            has_count = not isinstance(paginator, CursorPagination)
            base_path = settings.BASE_URL + self.path
            paged_schema = openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    "count": openapi.Schema(type=openapi.TYPE_INTEGER, example=5) if has_count else None,
                    "next": openapi.Schema(
                        type=openapi.TYPE_STRING,
                        format=openapi.FORMAT_URI,
                        x_nullable=True,
                        example=base_path + "?limit=5&offset=10",
                    ),
                    "previous": openapi.Schema(
                        type=openapi.TYPE_STRING,
                        format=openapi.FORMAT_URI,
                        x_nullable=True,
                        example=base_path + "?limit=5",
                    ),
                    "results": response_schema,
                },
                required=["count", "next", "previous", "results"],
            )

            if has_count:
                paged_schema.required.insert(0, "count")

        return paged_schema
