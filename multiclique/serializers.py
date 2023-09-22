from rest_framework import serializers
from rest_framework.fields import CharField, IntegerField, ListField
from rest_framework.serializers import ModelSerializer, Serializer

from multiclique import models


class InstallAccountAndPolicySerializer(serializers.Serializer):
    source = serializers.CharField(max_length=56)
    policy_preset = serializers.CharField()


class MultiCliquePolicySerializer(ModelSerializer):
    class Meta:
        model = models.MultiCliquePolicy
        fields = ("name", "active")


class MultiCliqueAccountSerializer(ModelSerializer):
    policy = CharField(source="policy.name", help_text="e.g.: ELIO_DAO")

    class Meta:
        model = models.MultiCliqueAccount
        fields = ("address", "public_keys", "default_threshold", "policy")


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
    public_keys = ListField(child=CharField(required=True), source="multiclique_account.public_keys")

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
            "public_keys",
        )
