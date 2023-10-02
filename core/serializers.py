import bleach
from django.conf import settings
from rest_framework.fields import CharField, EmailField, IntegerField, URLField
from rest_framework.serializers import ModelSerializer, Serializer, ValidationError

from core import models
from core.utils import B64ImageField


class StatsSerializer(Serializer):  # noqa
    dao_count = IntegerField(min_value=0)
    account_count = IntegerField(min_value=0)
    proposal_count = IntegerField(min_value=0)
    vote_count = IntegerField(min_value=0)


class UpdateConfigSerializer(Serializer):  # noqa
    core_contract_address = CharField(required=False)
    votes_contract_address = CharField(required=False)
    assets_wasm_hash = CharField(required=False)
    multiclique_wasm_hash = CharField(required=False)
    policy_wasm_hash = CharField(required=False)
    blockchain_url = CharField(required=False)
    network_passphrase = CharField(required=False)


class ConfigSerializer(Serializer):  # noqa
    deposit_to_create_dao = IntegerField(
        min_value=0, help_text="Amount of native balance required to deposit when creating a DAO."
    )
    deposit_to_create_proposal = IntegerField(
        min_value=0, help_text="Amount of native balance required to deposit when creating a Proposal."
    )
    block_creation_interval = IntegerField(min_value=0, help_text="In seconds.")
    core_contract_address = CharField()
    votes_contract_address = CharField()
    assets_wasm_hash = CharField()
    multiclique_wasm_hash = CharField()
    policy_wasm_hash = CharField()
    blockchain_url = CharField()
    network_passphrase = CharField()
    current_block_number = IntegerField(allow_null=True, required=False)
    horizon_server_standalone = CharField()
    horizon_server_futurenet = CharField()
    horizon_server_testnet = CharField()
    horizon_server_mainnet = CharField()


class BalanceSerializer(Serializer):  # noqa
    free = IntegerField(min_value=0)
    reserved = IntegerField(min_value=0)
    misc_frozen = IntegerField(min_value=0)
    fee_frozen = IntegerField(min_value=0)


class AccountSerializerDetail(ModelSerializer):
    balance = BalanceSerializer(required=True)

    class Meta:
        model = models.Account
        fields = ("address", "balance")


class AccountSerializerList(ModelSerializer):
    class Meta:
        model = models.Account
        fields = ("address",)


class DaoSerializer(ModelSerializer):
    owner_id = CharField(required=True)
    asset_id = CharField(source="asset.id", required=False)
    asset_address = CharField(source="asset.address", required=False)
    proposal_duration = IntegerField(source="governance.proposal_duration", help_text="Proposal duration in blocks.")
    proposal_token_deposit = IntegerField(
        source="governance.proposal_token_deposit",
        help_text="Token deposit required to create a Proposal",
        required=False,
    )
    min_threshold_configuration = IntegerField(
        source="governance.min_threshold_configuration",
        help_text="ayes >= nays + token_supply / 1024 * min_threshold_configuration",
    )

    class Meta:
        model = models.Dao
        fields = (
            "id",
            "name",
            "contract_id",
            "creator_id",
            "owner_id",
            "asset_id",
            "asset_address",
            "proposal_duration",
            "proposal_token_deposit",
            "min_threshold_configuration",
            "setup_complete",
            "metadata",
            "metadata_url",
            "metadata_hash",
        )


class AddDaoMetadataSerializer(Serializer):  # noqa
    description_short = CharField(required=False)
    description_long = CharField(required=False)
    email = EmailField(required=False)
    logo = B64ImageField(
        help_text=f"B64 encoded image string.\nAllowed image types are: {', '.join(B64ImageField.ALLOWED_TYPES)}."
    )

    @staticmethod
    def validate_logo(logo):
        if logo.size > settings.MAX_LOGO_SIZE:
            raise ValidationError(f"The uploaded file is too big. Max size: {settings.MAX_LOGO_SIZE / 1_000_000} mb.")
        return logo


class DaoMetadataResponseSerializer(Serializer):  # noqa
    class MetadataSerializer(Serializer):  # noqa
        description_short = CharField(required=False)
        description_long = CharField(required=False)
        email = EmailField(required=False)

        class Meta:  # noqa
            ref_name = "ResponseMetadataSerializer"

        class ImagagesSerializer(Serializer):  # noqa
            class Meta:  # noqa
                ref_name = "ResponseImageSerializer"

            class LogoSerializer(Serializer):  # noqa
                class UrlSerializer(Serializer):  # noqa
                    url = URLField()

                content_type = CharField()
                small = UrlSerializer()
                medium = UrlSerializer()
                large = UrlSerializer()

            logo = LogoSerializer()

        images = ImagagesSerializer()

    metadata = MetadataSerializer()
    metadata_hash = CharField()
    metadata_url = URLField()


class AssetSerializer(ModelSerializer):
    id = CharField(required=True)
    address = CharField(required=True)
    dao_id = CharField(required=True)
    owner_id = CharField(required=True)
    total_supply = IntegerField(min_value=0)

    class Meta:
        model = models.Asset
        fields = ("id", "address", "dao_id", "owner_id", "total_supply")


class AssetHoldingSerializer(ModelSerializer):
    asset_id = CharField(required=True)
    asset_address = CharField(source="asset.address", required=True)
    owner_id = CharField(required=True)
    balance = IntegerField(min_value=0)

    class Meta:
        model = models.AssetHolding
        fields = ("id", "asset_id", "asset_address", "owner_id", "balance")


class VotesSerializer(Serializer):  # noqa
    pro = IntegerField(min_value=0)
    contra = IntegerField(min_value=0)
    abstained = IntegerField(min_value=0)
    total = IntegerField(min_value=0)

    def to_representation(self, instance):
        pro, contra, abstained, total = 0, 0, 0, 0
        for vote in instance.instance.votes.all():
            total += vote.voting_power
            match vote.in_favor:
                case True:
                    pro += vote.voting_power
                case False:
                    contra += vote.voting_power
                case _:
                    abstained += vote.voting_power
        return {"pro": pro, "contra": contra, "abstained": abstained, "total": total}


class ProposalSerializer(ModelSerializer):
    votes = VotesSerializer()
    birth_block_number = IntegerField(min_value=0)

    class Meta:
        model = models.Proposal
        fields = (
            "id",
            "dao_id",
            "creator_id",
            "status",
            "fault",
            "votes",
            "metadata",
            "metadata_url",
            "metadata_hash",
            "birth_block_number",
            "setup_complete",
        )


class AddProposalMetadataSerializer(Serializer):  # noqa
    title = CharField(max_length=128)
    description = CharField(max_length=10000)
    url = URLField()

    def validate(self, attrs: dict):
        allowed_tags = {*bleach.ALLOWED_TAGS, "p", "br", "u"}
        allowed_attrs = bleach.ALLOWED_ATTRIBUTES
        allowed_attrs["a"] += ["target", "rel"]
        attrs["description"] = bleach.clean(attrs["description"], tags=allowed_tags, attributes=allowed_attrs)
        return attrs


class ProposalMetadataResponseSerialzier(Serializer):  # noqa
    metadata = AddProposalMetadataSerializer()
    metadata_hash = CharField()
    metadata_url = URLField()


class ReportFaultedSerializer(ModelSerializer):
    proposal_id = CharField(max_length=128)
    reason = CharField(max_length=1024)

    class Meta:
        model = models.ProposalReport
        fields = ("proposal_id", "reason")

    def create(self, validated_data):
        return models.ProposalReport.objects.create(**validated_data)


class ChallengeSerializer(Serializer):  # noqa
    challenge = CharField(required=True, help_text=f"Valid for {settings.CHALLENGE_LIFETIME}s.")
