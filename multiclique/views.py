import os

from django.conf import settings
from rest_framework import status
from rest_framework.decorators import api_view
from rest_framework.response import Response
from stellar_sdk import TransactionBuilder
from stellar_sdk.exceptions import PrepareTransactionException

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
