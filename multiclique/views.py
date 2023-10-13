import json
import logging
import secrets

from django.conf import settings
from django.core.cache import cache
from django.db.models import Prefetch
from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema
from rest_framework.decorators import action
from rest_framework.mixins import CreateModelMixin
from rest_framework.response import Response
from rest_framework.status import HTTP_200_OK, HTTP_201_CREATED, HTTP_400_BAD_REQUEST
from rest_framework.viewsets import GenericViewSet, ReadOnlyModelViewSet
from rest_framework_simplejwt.serializers import TokenRefreshSerializer

from core.view_utils import (
    IsAuthenticated,
    MultiQsLimitOffsetPagination,
    SearchableMixin,
)
from multiclique import models, serializers

slack_logger = logging.getLogger("alerts.slack")


class MultiCliqueContractViewSet(GenericViewSet):
    @swagger_auto_schema(
        operation_id="Generate MultiClique Contract XDR",
        operation_description="Generates XDR to create a MultiClique Contract instance",
        request_body=serializers.CreateMultiCliqueContractSerializer,
        responses={200: openapi.Response("", serializers.MultiCliqueContractXDRSerializer)},
        security=[{"Basic": []}],
    )
    @action(
        methods=["POST"],
        detail=False,
        url_path="create-multiclique-xdr",
    )
    def create_multiclique_contract_xdr(self, request, *args, **kwargs):
        from core.soroban import SorobanException, soroban_service

        serializer = serializers.CreateMultiCliqueContractSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            xdr = soroban_service.create_install_contract_transaction(
                source_account_address=serializer.data["source_account_address"],
                wasm_id=soroban_service.set_config()["multiclique_wasm_hash"],
            ).to_xdr()
        except SorobanException:
            return Response(data={"error": "Unable to prepare transaction"}, status=HTTP_400_BAD_REQUEST)

        serializer = serializers.MultiCliqueContractXDRSerializer(data={"xdr": xdr})
        serializer.is_valid(raise_exception=True)
        return Response(data=serializer.data, status=HTTP_201_CREATED)

    @swagger_auto_schema(
        operation_id="Generate Policy Contract XDR",
        operation_description="Generates XDR to create a Policy Contract instance",
        request_body=serializers.CreatePolicyContractSerializer,
        responses={200: openapi.Response("", serializers.MultiCliqueContractXDRSerializer)},
        security=[{"Basic": []}],
    )
    @action(
        methods=["POST"],
        detail=False,
        url_path="create-policy-xdr",
    )
    def create_policy_contract_xdr(self, request, *args, **kwargs):
        from core.soroban import SorobanException, soroban_service

        serializer = serializers.CreatePolicyContractSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            xdr = soroban_service.create_install_contract_transaction(
                source_account_address=serializer.data["source_account_address"],
                wasm_id=soroban_service.set_config()["policy_wasm_hash"],
            ).to_xdr()
        except SorobanException:
            return Response(data={"error": "Unable to prepare transaction"}, status=HTTP_400_BAD_REQUEST)

        serializer = serializers.MultiCliqueContractXDRSerializer(data={"xdr": xdr})
        serializer.is_valid(raise_exception=True)
        return Response(data=serializer.data, status=HTTP_201_CREATED)


class MultiCliqueAccountViewSet(ReadOnlyModelViewSet, CreateModelMixin, SearchableMixin):
    queryset = models.MultiCliqueAccount.objects.all()
    pagination_class = MultiQsLimitOffsetPagination
    serializer_class = serializers.MultiCliqueAccountSerializer
    search_fields = ["address", "signatories"]
    filter_fields = ["signatories"]
    ordering_fields = ["address"]
    lookup_field = "address"

    def get_queryset(self):
        return self.queryset.select_related("policy").prefetch_related(
            Prefetch("signatories", queryset=models.MultiCliqueSignatory.objects.order_by("address"))
        )

    @swagger_auto_schema(
        operation_id="Create / Update MultiCliqueAccount",
        operation_description="Creates or updates a MultiCliqueAccount",
        request_body=serializers.MultiCliqueAccountSerializer,
        responses={
            200: openapi.Response("", serializers.MultiCliqueAccountSerializer),
        },
        security=[{"Basic": []}],
    )
    def create(self, request, *args, **kwargs):
        from core.soroban import soroban_service

        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        soroban_service.set_trusted_contract_ids()
        data = serializer.data
        return Response(data=data, status=HTTP_200_OK, headers=self.get_success_headers(data=data))

    @swagger_auto_schema(
        method="GET",
        operation_id="Challenge",
        operation_description="Retrieves a challenge to login for the given MultiClique Account.",
        responses=openapi.Responses(
            responses={HTTP_200_OK: openapi.Response("", serializers.MultiCliqueChallengeSerializer)}
        ),
        security=[{"Basic": []}],
    )
    @action(
        methods=["GET"],
        detail=True,
        url_path="challenge",
    )
    def challenge(self, request, **_):
        challenge_token = secrets.token_hex(64)
        cache.set(key=self.get_object().address, value=challenge_token, timeout=settings.CHALLENGE_LIFETIME)
        return Response(status=HTTP_200_OK, data={"challenge": challenge_token})

    @swagger_auto_schema(
        method="POST",
        operation_id="Create JWT Token",
        operation_description="Creates a JWT Token for the given MultiClique Account.",
        request_body=serializers.SwaggerMultiCliqueAuthSerializer,
        responses=openapi.Responses(responses={HTTP_200_OK: openapi.Response("", serializers.JWTTokenSerializer)}),
        security=[{"Basic": []}],
    )
    @action(
        methods=["POST"],
        detail=True,
        url_path="create-jwt-token",
    )
    def create_jwt_token(self, request, **kwargs):
        serializer = serializers.MultiCliqueAuthSerializer(data={"address": kwargs["address"], **request.data})
        serializer.is_valid(raise_exception=True)
        return Response(data=serializer.data, status=HTTP_200_OK)

    @swagger_auto_schema(
        method="POST",
        operation_id="Refresh JWT Token",
        operation_description="Refreshes a JWT Token for the given MultiClique Account.",
        request_body=serializers.JWTTokenSerializer,
        responses=openapi.Responses(responses={HTTP_200_OK: openapi.Response("", serializers.JWTTokenSerializer)}),
        security=[{"Basic": []}],
    )
    @action(
        methods=["POST"],
        detail=True,
        url_path="refresh-jwt-token",
    )
    def refresh_jwt_token(self, request, **kwargs):
        serializer = TokenRefreshSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response(data=serializer.data, status=HTTP_200_OK)


class MultiCliqueTransactionViewSet(ReadOnlyModelViewSet, CreateModelMixin, SearchableMixin):
    queryset = models.MultiCliqueTransaction.objects.all()
    serializer_class = serializers.MultiCliqueTransactionSerializer
    filter_fields = ["xdr"]
    ordering_fields = ["call_func", "status", "executed_at"]
    permission_classes = [IsAuthenticated]

    def filter_queryset(self, queryset):
        return super().filter_queryset(queryset).filter(multiclique_account__address=self.request.user.id)

    def get_queryset(self):
        return self.queryset.prefetch_related(
            "approvals__signatory", "rejections__signatory", "multiclique_account__signatories"
        )

    @swagger_auto_schema(
        operation_id="Create MultiCliqueTransaction",
        operation_description="Creates a MultiCliqueTransaction",
        request_body=serializers.CreateMultiCliqueTransactionSerializer,
        responses={
            201: openapi.Response("", serializers.MultiCliqueTransactionSerializer),
        },
        security=[{"Bearer": []}],
    )
    def create(self, request, *args, **kwargs):
        from core.soroban import SorobanException, soroban_service

        serializer = serializers.CreateMultiCliqueTransactionSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.data

        try:
            xdr_data = soroban_service.analyze_transaction(obj=(xdr := data["xdr"]))
        except SorobanException as exc:
            return Response(data={**exc.ctx, "error": str(exc)}, status=HTTP_400_BAD_REQUEST)

        try:
            acc = models.MultiCliqueAccount.objects.get(address=request.user.id)
        except models.MultiCliqueAccount.DoesNotExist:
            return Response(data={"error": "MultiCliqueAccount does not exist."}, status=HTTP_400_BAD_REQUEST)

        serializer = self.get_serializer(
            data={
                "xdr": xdr,
                "multiclique_account": acc,
                "nonce": xdr_data["nonce"],
                "ledger": xdr_data["ledger"],
                "call_func": xdr_data["func_name"],
                "call_args": xdr_data["func_args"],
                "preimage_hash": xdr_data["preimage_hash"],
                "approvals": [],
                "rejections": [],
            }
        )
        if not serializer.is_valid():
            slack_logger.error(f"{serializer.errors} ctx: {json.dumps(xdr_data)}")
            return Response(data={"error": "Error during Transaction creation"}, status=HTTP_400_BAD_REQUEST)

        serializer.save()
        res_data = serializer.data
        return Response(data=res_data, status=HTTP_201_CREATED, headers=self.get_success_headers(data=res_data))

    @swagger_auto_schema(
        operation_id="Update MultiCliqueTransaction",
        operation_description="Updates a MultiCliqueTransaction",
        request_body=serializers.UpdateMultiCliqueTransactionSerializer,
        responses={
            201: openapi.Response("", serializers.MultiCliqueTransactionSerializer),
        },
        security=[{"Bearer": []}],
    )
    def partial_update(self, request, *args, **kwargs):
        from core.soroban import SorobanException, update_transaction

        serializer = serializers.UpdateMultiCliqueTransactionSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        serializer = self.get_serializer(instance=self.get_object(), data=serializer.data, partial=True)
        if not serializer.is_valid():
            slack_logger.error(serializer.errors)
            return Response(data={"error": "Error during Transaction update"}, status=HTTP_400_BAD_REQUEST)

        try:
            update_transaction(transaction=serializer.save())
        except SorobanException:
            return Response(data={"error": "Error during Transaction update"}, status=HTTP_400_BAD_REQUEST)

        res_data = self.get_serializer(instance=self.get_object()).data
        return Response(data=res_data, status=HTTP_200_OK, headers=self.get_success_headers(data=res_data))
