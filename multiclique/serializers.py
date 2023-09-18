from rest_framework import serializers
from rest_framework.fields import CharField, IntegerField, ListField
from rest_framework.serializers import ModelSerializer

from multiclique import models


class InstallAccountAndPolicySerializer(serializers.Serializer):
    source = serializers.CharField(max_length=56)
    policy_preset = serializers.CharField()


class MultiCliquePolicySerializer(ModelSerializer):
    class Meta:
        model = models.MultiCliquePolicy
        fields = ("name", "active")


class MultiCliqueAccountSerializer(ModelSerializer):
    class Meta:
        model = models.MultiCliqueAccount
        fields = ("address", "public_keys", "threshold", "policy")


class CreateMultiCliqueAccountSerializer(ModelSerializer):
    public_keys = ListField(child=CharField(required=True), required=True)
    default_threshold = IntegerField(required=True)
    policy = CharField(required=True)

    class Meta:
        model = models.MultiCliqueAccount
        fields = ("public_keys", "default_threshold", "policy")


class MultiCliqueTransactionSerializer(ModelSerializer):
    multiclique_address = CharField(source="multiclique.address")
    default_threshold = IntegerField(source="multiclique.threshold")
    public_keys = ListField(child=CharField(required=True), source="multiclique.public_keys")

    class Meta:
        model = models.MultiCliqueTransaction
        fields = (
            "xdr",
            "preimage_hash",
            "call_func",
            "call_args",
            "signers",
            "status",
            "executed_at",
            "created_at",
            "updated_at",
            "multiclique_address",
            "default_threshold",
            "public_keys",
        )
