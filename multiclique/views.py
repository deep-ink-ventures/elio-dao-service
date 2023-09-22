import os
import re

from django.conf import settings
from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema
from rest_framework import status
from rest_framework.decorators import api_view
from rest_framework.exceptions import ValidationError
from rest_framework.mixins import CreateModelMixin, UpdateModelMixin
from rest_framework.response import Response
from rest_framework.status import HTTP_200_OK, HTTP_201_CREATED, HTTP_400_BAD_REQUEST
from rest_framework.viewsets import ReadOnlyModelViewSet
from stellar_sdk import TransactionBuilder
from stellar_sdk.exceptions import PrepareTransactionException

from core.soroban import InvalidXDRException
from core.view_utils import MultiQsLimitOffsetPagination, SearchableMixin
from multiclique import models, serializers
from multiclique.serializers import InstallAccountAndPolicySerializer

MULTICLIQUE_WASM = "e5fafe7d0240f37cb75ce391398a4e0d1d628eff89d04f62d2cde65489aa0f8e"
ELIO_PRESET_WASM = "26b9b25c6d500260de2aeef80e8810643a95223f003d2607a6006e4ff26db211"


@api_view(["POST"])
def install_account_and_policy(request):
    from core.soroban import soroban_service

    if request.method == "POST":
        serializer = InstallAccountAndPolicySerializer(data=request.data)
        if serializer.is_valid():
            source_account = serializer.data["source"]
            source = soroban_service.soroban.load_account(source_account)
            policy_preset = serializer.data["policy_preset"]

            core_salt = os.urandom(32)
            tx = (
                TransactionBuilder(source, settings.NETWORK_PASSPHRASE)
                .set_timeout(300)
                .append_create_contract_op(wasm_id=MULTICLIQUE_WASM, address=source_account, salt=core_salt)
            )

            core_envelope = tx.build()
            try:
                core_envelope = soroban_service.soroban.prepare_transaction(core_envelope)
            except PrepareTransactionException:
                return Response({"error": "Unable to prepare transaction"}, status=status.HTTP_400_BAD_REQUEST)

            tx = TransactionBuilder(source, settings.NETWORK_PASSPHRASE).set_timeout(300)

            preset_salt = os.urandom(32)
            if policy_preset == "ELIO_DAO":
                tx.append_create_contract_op(wasm_id=ELIO_PRESET_WASM, address=source_account, salt=preset_salt)

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
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class MultiCliqueAccountViewSet(ReadOnlyModelViewSet, CreateModelMixin, SearchableMixin):
    queryset = models.MultiCliqueAccount.objects.all()
    pagination_class = MultiQsLimitOffsetPagination
    serializer_class = serializers.MultiCliqueAccountSerializer
    search_fields = ["address", "public_keys"]
    ordering_fields = ["address"]
    lookup_field = "address"

    def get_queryset(self):
        return self.queryset.select_related("policy")

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
        try:
            serializer.is_valid(raise_exception=True)
        except ValidationError as err:
            # we ignore unique address error, since we want to update these accounts if they exist already
            if not (addr_err := err.detail.get("address")) or addr_err[0].code != "unique":
                raise
        data = serializer.data
        # to UPPER_SNAKE_CASE
        policy_name = re.sub(r"_+", "_", re.sub(r"[\s|\-|\.]+", "_", data["policy"].upper()))  # noqa
        multiclique_acc, created = models.MultiCliqueAccount.objects.update_or_create(
            address=data["address"],
            defaults={
                "public_keys": data["public_keys"],
                "default_threshold": data["default_threshold"],
                "policy": models.MultiCliquePolicy.objects.get_or_create(name=policy_name)[0],
            },
        )
        res_data = self.get_serializer(multiclique_acc).data
        return Response(
            data=res_data,
            status=HTTP_201_CREATED if created else HTTP_200_OK,
            headers=self.get_success_headers(data=res_data),
        )


class MultiCliqueTransactionViewSet(ReadOnlyModelViewSet, CreateModelMixin, UpdateModelMixin, SearchableMixin):
    queryset = models.MultiCliqueTransaction.objects.all()
    serializer_class = serializers.MultiCliqueTransactionSerializer
    filter_fields = ["xdr", "multiclique_account__address"]
    ordering_fields = ["call_func", "status", "executed_at"]
    lookup_field = "xdr"

    def get_queryset(self):
        return self.queryset.select_related("multiclique_account")

    @swagger_auto_schema(
        operation_id="Create MultiCliqueTransaction",
        operation_description="Creates a MultiCliqueTransaction",
        request_body=serializers.CreateMultiCliqueTransactionSerializer,
        responses={
            201: openapi.Response("", serializers.MultiCliqueTransactionSerializer),
        },
        security=[{"Basic": []}],
    )
    def create(self, request, *args, **kwargs):
        from core.soroban import soroban_service

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
