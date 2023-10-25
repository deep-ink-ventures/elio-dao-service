from django.conf import settings
from rest_framework.exceptions import ValidationError
from rest_framework.fields import CharField, ChoiceField, IntegerField
from rest_framework.serializers import ModelSerializer, Serializer
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

from multiclique import models


class CreateMultiCliqueContractSerializer(Serializer):
    source_account_address = CharField(max_length=56)


class MultiCliqueContractSerializer(ModelSerializer):
    limit = IntegerField(required=False)
    already_spent = IntegerField(required=False)
    type = ChoiceField(
        choices=models.MultiCliqueContractType.as_choices(), default=models.MultiCliqueContractType.UNKNOWN
    )

    class Meta:
        model = models.MultiCliqueContract
        fields = ("address", "limit", "already_spent", "type")


class CreatePolicyContractSerializer(Serializer):
    source_account_address = CharField(max_length=56)
    policy_preset = CharField(help_text='currently only supports "ELIO_DAO"')

    @staticmethod
    def validate_policy_preset(value):
        if value != "ELIO_DAO":
            raise ValidationError('currently only "ELIO_DAO" is supported as policy preset')
        return value


class MultiCliqueContractXDRSerializer(Serializer):
    xdr = CharField()


class MultiCliquePolicySerializer(ModelSerializer):
    contracts = MultiCliqueContractSerializer(many=True, read_only=True)

    class Meta:
        model = models.MultiCliquePolicy
        fields = ("address", "name", "contracts")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # we don't want the unique validator here
        self.fields["address"].validators.pop(0)

    @staticmethod
    def validate_name(value):
        if value != "ELIO_DAO":
            raise ValidationError('currently only "ELIO_DAO" is supported as policy preset')
        return value


class MultiCliqueSignatorySerializer(ModelSerializer):
    class Meta:
        model = models.MultiCliqueSignatory
        fields = ("address", "name")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # we don't want the unique validator here
        self.fields["address"].validators.pop(0)


class MultiCliqueAccountSerializer(ModelSerializer):
    policy = MultiCliquePolicySerializer(required=False)
    signatories = MultiCliqueSignatorySerializer(many=True, default=[])

    class Meta:
        model = models.MultiCliqueAccount
        fields = ("address", "name", "signatories", "default_threshold", "policy")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # we don't want the unique validators here
        self.fields["address"].validators.pop(0)

    def create(self, validated_data):
        signatories = models.MultiCliqueSignatory.objects.bulk_create(
            [models.MultiCliqueSignatory(**entry) for entry in validated_data["signatories"]], ignore_conflicts=True
        )
        multiclique_acc, created = models.MultiCliqueAccount.objects.update_or_create(
            address=validated_data["address"],
            defaults={
                "name": validated_data["name"],
                "default_threshold": validated_data["default_threshold"],
                "policy": models.MultiCliquePolicy.objects.update_or_create(
                    address=validated_data["policy"]["address"],
                    defaults={"name": validated_data["policy"]["name"]},
                )[0],
            },
        )
        multiclique_acc.signatories.set(signatories)
        multiclique_acc.save()
        return multiclique_acc


class MultiCliqueSignatureSerializer(Serializer):
    signature = CharField()
    signatory = MultiCliqueSignatorySerializer()


class MultiCliqueTransactionSerializer(ModelSerializer):
    multiclique_address = CharField(source="multiclique_account.address", read_only=True)
    default_threshold = IntegerField(source="multiclique_account.default_threshold", read_only=True)
    approvals = MultiCliqueSignatureSerializer(many=True)
    rejections = MultiCliqueSignatureSerializer(many=True)
    signatories = MultiCliqueSignatorySerializer(many=True, source="multiclique_account.signatories", read_only=True)

    class Meta:
        model = models.MultiCliqueTransaction
        fields = (
            "id",
            "xdr",
            "preimage_hash",
            "call_func",
            "call_args",
            "approvals",
            "rejections",
            "status",
            "executed_at",
            "created_at",
            "updated_at",
            "multiclique_address",
            "default_threshold",
            "signatories",
        )

    @staticmethod
    def _create_signatures(validated_data):
        signatories = []
        approvals = []
        rejections = []
        for entry in validated_data.pop("approvals", []):
            signatory = models.MultiCliqueSignatory(
                address=entry["signatory"]["address"], name=entry["signatory"].get("name")
            )
            signatories.append(signatory)
            approvals.append(models.MultiCliqueSignature(signatory=signatory, signature=entry["signature"]))
        for entry in validated_data.pop("rejections", []):
            signatory = models.MultiCliqueSignatory(
                address=entry["signatory"]["address"], name=entry["signatory"].get("name")
            )
            signatories.append(signatory)
            rejections.append(models.MultiCliqueSignature(signatory=signatory, signature=entry["signature"]))

        signatures = []
        if approvals or rejections:
            models.MultiCliqueSignatory.objects.bulk_create(signatories, ignore_conflicts=True)
            signatures = models.MultiCliqueSignature.objects.bulk_create(
                [*approvals, *rejections], ignore_conflicts=True
            )

        return signatures, len(approvals)

    def create(self, validated_data):
        validated_data["multiclique_account"] = self.initial_data["multiclique_account"]
        validated_data["nonce"] = self.initial_data["nonce"]
        validated_data["ledger"] = self.initial_data["ledger"]

        signatures, approval_count = self._create_signatures(validated_data)
        txn = models.MultiCliqueTransaction.objects.create(**validated_data)
        if signatures:
            if approval_count:
                txn.approvals.set(signatures[:approval_count])
            if len(signatures) > approval_count:
                txn.rejections.set(signatures[approval_count:])
            txn.save()

        return txn

    def update(self, instance, validated_data):
        signatures, approval_count = self._create_signatures(validated_data)
        if signatures:
            if approval_count:
                approvals = signatures[:approval_count]
                instance.approvals.add(*approvals)
                instance.rejections.through.objects.filter(
                    multicliquesignature_id__in=[approval.pk for approval in approvals],
                    multicliquetransaction_id=instance.id,
                ).delete()
            if len(signatures) > approval_count:
                rejections = signatures[approval_count:]
                instance.rejections.add(*rejections)
                instance.approvals.through.objects.filter(
                    multicliquesignature_id__in=[rejection.pk for rejection in rejections],
                    multicliquetransaction_id=instance.id,
                ).delete()

        if validated_data:
            for attr, value in validated_data.items():
                setattr(instance, attr, value)

        instance.save()
        return instance


class CreateMultiCliqueTransactionSerializer(Serializer):
    xdr = CharField(required=True)

    class Meta:
        fields = ("xdr",)


class UpdateMultiCliqueTransactionSerializer(Serializer):
    approvals = MultiCliqueSignatureSerializer(many=True, required=False)
    rejections = MultiCliqueSignatureSerializer(many=True, required=False)


class SwaggerMultiCliqueAuthSerializer(Serializer):
    signature = CharField()


class MultiCliqueAuthSerializer(Serializer):
    address = CharField(write_only=True)
    signature = CharField(write_only=True)

    access = CharField(read_only=True)
    refresh = CharField(read_only=True)

    def validate(self, attrs):
        from core.soroban import soroban_service

        if not (address := attrs.get("address")):
            raise ValidationError('Must include "multiclique_address".', code="authorization")
        if not (signature := attrs.get("signature")):
            raise ValidationError('Must include "signature".', code="authorization")

        try:
            acc = models.MultiCliqueAccount.objects.get(address=address)
        except models.MultiCliqueAccount.DoesNotExist:
            raise ValidationError("MultiCliqueAccount does not exist.", code="authorization")

        if not any(
            soroban_service.verify(address=addr, challenge_address=address, signature=signature)
            for addr in (address, *acc.signatories.values_list("address", flat=True))
        ):
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
