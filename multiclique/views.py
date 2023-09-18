import os

from django.conf import settings
from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema
from rest_framework import status
from rest_framework.decorators import api_view
from rest_framework.mixins import CreateModelMixin
from rest_framework.response import Response
from rest_framework.status import HTTP_200_OK, HTTP_201_CREATED
from rest_framework.viewsets import ReadOnlyModelViewSet
from stellar_sdk import TransactionBuilder
from stellar_sdk.exceptions import PrepareTransactionException

from core.view_utils import MultiQsLimitOffsetPagination, SearchableMixin

from . import models, serializers
from .serializers import InstallAccountAndPolicySerializer

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


class MultiCliqueViewSet(ReadOnlyModelViewSet, CreateModelMixin, SearchableMixin):
    queryset = models.MultiCliqueAccount.objects.all()
    pagination_class = MultiQsLimitOffsetPagination
    serializer_class = serializers.MultiCliqueAccountSerializer
    search_fields = ["address", "public_keys"]
    ordering_fields = ["address"]
    lookup_field = "address"

    @swagger_auto_schema(
        operation_id="Create / Update MultiCliqueAccount Account",
        operation_description="Creates or updates a MultiCliqueAccount Account",
        request_body=serializers.CreateMultiCliqueAccountSerializer,
        responses={201: openapi.Response("", serializers.MultiCliqueAccountSerializer)},
        security=[{"Basic": []}],
    )
    def create(self, request, *args, **kwargs):
        serializer = serializers.CreateMultiCliqueAccountSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.data

        # todo
        # address = substrate_service.create_multisig_account(
        #     signers=data["public_keys"], threshold=data["threshold"]
        # ).ss58_address
        multiclique_acc, created = models.MultiCliqueAccount.objects.update_or_create(
            address="TODO",
            defaults={
                "public_keys": data["public_keys"],
                "threshold": data["threshold"],
                "policy": models.MultiCliquePolicy.objects.get_or_create(name=data["policy"])[0],
            },
        )
        res_data = self.get_serializer(multiclique_acc).data
        return Response(
            data=res_data,
            status=HTTP_201_CREATED if created else HTTP_200_OK,
            headers=self.get_success_headers(data=res_data),
        )


class MultiCliqueTransactionViewSet(ReadOnlyModelViewSet, SearchableMixin):
    queryset = models.MultiCliqueTransaction.objects.all()
    serializer_class = serializers.MultiCliqueTransactionSerializer
    filter_fields = ["xdr", "multiclique_account__address"]
    ordering_fields = ["call_func", "status", "executed_at"]
    lookup_field = "xdr"
