from django.conf import settings
from rest_framework import serializers
from rest_framework.exceptions import ValidationError
from rest_framework.fields import CharField, IntegerField
from rest_framework.serializers import ModelSerializer, Serializer
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

from multiclique import models


class InstallAccountAndPolicySerializer(serializers.Serializer):
    source = serializers.CharField(max_length=56)
    policy_preset = serializers.CharField()


class MultiCliquePolicySerializer(ModelSerializer):
    class Meta:
        model = models.MultiCliquePolicy
        fields = ("name", "active")


class MultiCliqueSignatorySerializer(ModelSerializer):
    class Meta:
        model = models.MultiCliqueSignatory
        fields = ("address", "name")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # we don't want the unique validator here
        self.fields["address"].validators.pop(0)


class MultiCliqueAccountSerializer(ModelSerializer):
    policy = CharField(source="policy.name", help_text="e.g.: ELIO_DAO")
    signatories = MultiCliqueSignatorySerializer(many=True)

    class Meta:
        model = models.MultiCliqueAccount
        fields = ("address", "name", "signatories", "default_threshold", "policy")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # we don't want the unique validators here
        self.fields["address"].validators.pop(0)
        self.fields["policy"].validators.pop(0)


class CreateMultiCliqueTransactionSerializer(Serializer):
    xdr = CharField(required=True)
    multiclique_address = CharField(required=True)

    class Meta:
        fields = (
            "xdr",
            "multiclique_address",
        )


class MultiCliqueTransactionSerializer(ModelSerializer):
    multiclique_address = CharField(source="multiclique_account.address")
    default_threshold = IntegerField(source="multiclique_account.default_threshold")
    signatories = MultiCliqueSignatorySerializer(many=True, source="multiclique_account.signatories")

    class Meta:
        model = models.MultiCliqueTransaction
        fields = (
            "xdr",
            "preimage_hash",
            "call_func",
            "call_args",
            "approvers",
            "rejecters",
            "status",
            "executed_at",
            "created_at",
            "updated_at",
            "multiclique_address",
            "default_threshold",
            "signatories",
        )


class SwaggerMultiCliqueAuthSerializer(Serializer):
    signature = CharField()


class MultiCliqueAuthSerializer(Serializer):
    address = CharField(write_only=True)
    signature = CharField(write_only=True)

    access = CharField(read_only=True)
    refresh = CharField(read_only=True)

    def validate(self, attrs):
        from core.soroban import soroban_service

        if not (addr := attrs.get("address")):
            raise ValidationError('Must include "multiclique_address".', code="authorization")
        if not (sig := attrs.get("signature")):
            raise ValidationError('Must include "signature".', code="authorization")

        try:
            acc = models.MultiCliqueAccount.objects.get(address=addr)
        except models.MultiCliqueAccount.DoesNotExist:
            raise ValidationError("MultiCliqueAccount does not exist.", code="authorization")

        if not soroban_service.verify(address=addr, challenge_address=addr, signature=sig):
            raise ValidationError("Signature does not match.", code="authorization")

        refresh = TokenObtainPairSerializer.get_token(acc)
        attrs["refresh"] = str(refresh)
        attrs["access"] = str(refresh.access_token)  # type: ignore
        return attrs


class JWTTokenSerializer(Serializer):
    access = CharField()
    refresh = CharField()


class MultiCliqueChallengeSerializer(Serializer):
    challenge = CharField(help_text=f"Valid for {settings.CHALLENGE_LIFETIME}s.")
