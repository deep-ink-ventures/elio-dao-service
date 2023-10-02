import os
import re
import secrets

from django.conf import settings
from django.core.cache import cache
from django.db import transaction
from django.db.models import Prefetch
from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema
from rest_framework import status
from rest_framework.decorators import action, api_view
from rest_framework.mixins import CreateModelMixin, UpdateModelMixin
from rest_framework.response import Response
from rest_framework.status import HTTP_200_OK, HTTP_201_CREATED, HTTP_400_BAD_REQUEST
from rest_framework.viewsets import ReadOnlyModelViewSet
from rest_framework_simplejwt.serializers import TokenRefreshSerializer
from stellar_sdk import TransactionBuilder
from stellar_sdk.exceptions import PrepareTransactionException

from core.view_utils import (
    IsAuthenticated,
    MultiQsLimitOffsetPagination,
    SearchableMixin,
)
from multiclique import models, serializers
from multiclique.serializers import InstallAccountAndPolicySerializer


@api_view(["POST"])
def install_account_and_policy(request):
    from core.soroban import soroban_service

    config = soroban_service.set_config()

    if request.method == "POST":
        serializer = InstallAccountAndPolicySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        source_account = serializer.data["source"]
        source = soroban_service.soroban.load_account(source_account)
        policy_preset = serializer.data["policy_preset"]

        core_salt = os.urandom(32)
        tx = (
            TransactionBuilder(source_account=source, network_passphrase=config["network_passphrase"])
            .set_timeout(300)
            .append_create_contract_op(wasm_id=config["multiclique_wasm_hash"], address=source_account, salt=core_salt)
        )

        core_envelope = tx.build()
        try:
            core_envelope = soroban_service.soroban.prepare_transaction(core_envelope)
        except PrepareTransactionException:
            return Response({"error": "Unable to prepare transaction"}, status=status.HTTP_400_BAD_REQUEST)

        tx = TransactionBuilder(source_account=source, network_passphrase=config["network_passphrase"]).set_timeout(300)

        preset_salt = os.urandom(32)
        if policy_preset == "ELIO_DAO":
            tx.append_create_contract_op(wasm_id=config["policy_wasm_hash"], address=source_account, salt=preset_salt)

        policy_envelope = tx.build()
        try:
            policy_envelope = soroban_service.soroban.prepare_transaction(policy_envelope)
        except PrepareTransactionException:
            return Response({"error": "Unable to prepare transaction"}, status=status.HTTP_400_BAD_REQUEST)

        return Response(
            {
                "core_xdr": core_envelope.to_xdr(),
                "policy_xdr": policy_envelope.to_xdr(),
            },
            status=status.HTTP_200_OK,
        )


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
            201: openapi.Response("", serializers.MultiCliqueAccountSerializer),
        },
        security=[{"Basic": []}],
    )
    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.data
        # to UPPER_SNAKE_CASE
        policy_name = re.sub(r"_+", "_", re.sub(r"[\s|\-|\.]+", "_", data["policy"].upper()))  # noqa
        with transaction.atomic():
            signatories = models.MultiCliqueSignatory.objects.bulk_create(
                [models.MultiCliqueSignatory(**entry) for entry in data["signatories"]], ignore_conflicts=True
            )
            multiclique_acc, created = models.MultiCliqueAccount.objects.update_or_create(
                address=data["address"],
                defaults={
                    "name": data["name"],
                    "default_threshold": data["default_threshold"],
                    "policy": models.MultiCliquePolicy.objects.get_or_create(name=policy_name)[0],
                },
            )
            multiclique_acc.signatories.set(signatories)
            multiclique_acc.save()
        res_data = self.get_serializer(multiclique_acc).data
        return Response(
            data=res_data,
            status=HTTP_201_CREATED if created else HTTP_200_OK,
            headers=self.get_success_headers(data=res_data),
        )

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


class MultiCliqueTransactionViewSet(ReadOnlyModelViewSet, CreateModelMixin, UpdateModelMixin, SearchableMixin):
    queryset = models.MultiCliqueTransaction.objects.all()
    serializer_class = serializers.MultiCliqueTransactionSerializer
    filter_fields = ["xdr", "multiclique_account__address"]
    ordering_fields = ["call_func", "status", "executed_at"]
    permission_classes = [IsAuthenticated]

    def filter_queryset(self, queryset):
        return super().filter_queryset(queryset).filter(multiclique_account__address=self.request.user.id)

    def get_queryset(self):
        return self.queryset.select_related("multiclique_account")

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
        from core.soroban import InvalidXDRException, soroban_service

        serializer = serializers.CreateMultiCliqueTransactionSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.data

        try:
            xdr_data = soroban_service.analyze_xdr(xdr=(xdr := data["xdr"]))
        except InvalidXDRException as exc:
            return Response(data={"error": exc.msg, "ctx": exc.ctx}, status=HTTP_400_BAD_REQUEST)

        try:
            acc = models.MultiCliqueAccount.objects.get(address=data["multiclique_address"])
        except models.MultiCliqueAccount.DoesNotExist:
            return Response(data={"error": "MultiCliqueAccount does not exist."}, status=HTTP_400_BAD_REQUEST)

        if len(signers := xdr_data["signers"]) == acc.default_threshold:
            txn_status = models.TransactionStatus.EXECUTABLE
        else:
            txn_status = models.TransactionStatus.PENDING

        txn = models.MultiCliqueTransaction.objects.create(
            xdr=xdr,
            multiclique_account=acc,
            call_func=xdr_data["func_name"],
            call_args=xdr_data["func_args"],
            approvers=signers,
            status=txn_status,
            preimage_hash=xdr_data["preimage_hash"],
        )
        res_data = self.get_serializer(txn).data
        return Response(data=res_data, status=HTTP_201_CREATED, headers=self.get_success_headers(data=res_data))
