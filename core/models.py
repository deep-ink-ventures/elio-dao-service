from django.db import models

from core import utils
from core.utils import ChoiceEnum


class TimestampableMixin(models.Model):
    created_at = models.DateTimeField(auto_now_add=True, editable=False)
    updated_at = models.DateTimeField(auto_now=True, editable=False)

    class Meta:
        abstract = True


class Contract(TimestampableMixin):
    id = models.CharField(primary_key=True, max_length=128)


class Account(TimestampableMixin):
    address = models.CharField(primary_key=True, max_length=128)

    class Meta:
        verbose_name = "Account"
        verbose_name_plural = "Accounts"


class Dao(TimestampableMixin):
    id = models.CharField(max_length=128, primary_key=True)
    contract = models.ForeignKey(Contract, on_delete=models.CASCADE)
    name = models.CharField(max_length=128, null=True)
    creator = models.ForeignKey(Account, related_name="created_daos", on_delete=models.SET_NULL, null=True)
    owner = models.ForeignKey(Account, related_name="owned_daos", on_delete=models.CASCADE)
    metadata = models.JSONField(null=True)
    metadata_url = models.CharField(max_length=256, null=True)
    metadata_hash = models.CharField(max_length=256, null=True)
    setup_complete = models.BooleanField(default=False)

    class Meta:
        verbose_name = "DAO"
        verbose_name_plural = "DAOs"


class GovernanceType(ChoiceEnum):
    MAJORITY_VOTE = "majority vote"


class Governance(TimestampableMixin):
    dao = models.OneToOneField(Dao, related_name="governance", on_delete=models.CASCADE)
    type = models.CharField(choices=GovernanceType.as_choices(), max_length=128, null=True)
    proposal_duration = utils.BiggerIntField()
    proposal_token_deposit = utils.BiggerIntField(null=True)
    min_threshold_configuration = utils.BiggerIntField()


class Asset(TimestampableMixin):
    address = models.CharField(max_length=128, primary_key=True)
    total_supply = utils.BiggerIntField()
    dao = models.OneToOneField(Dao, related_name="asset", on_delete=models.CASCADE)
    owner = models.ForeignKey(Account, related_name="assets", on_delete=models.CASCADE)

    class Meta:
        verbose_name = "Asset"
        verbose_name_plural = "Assets"


class AssetHolding(TimestampableMixin):
    asset = models.ForeignKey(Asset, related_name="holdings", on_delete=models.CASCADE)
    owner = models.ForeignKey(Account, related_name="holdings", on_delete=models.CASCADE)
    balance = utils.BiggerIntField()

    class Meta:
        db_table = "core_asset_holding"
        unique_together = ("asset", "owner")
        verbose_name = "Asset Holding"
        verbose_name_plural = "Asset Holdings"

    def __str__(self):
        return f"{self.asset_id} | {self.owner_id} | {self.balance}"


class ProposalStatus(ChoiceEnum):
    RUNNING = "running"
    PENDING = "pending"
    REJECTED = "rejected"
    IMPLEMENTED = "implemented"
    FAULTED = "faulted"


class Proposal(TimestampableMixin):
    id = models.CharField(max_length=128, primary_key=True)
    dao = models.ForeignKey(Dao, related_name="proposals", on_delete=models.CASCADE)
    creator = models.ForeignKey(Account, related_name="proposals", on_delete=models.SET_NULL, null=True)
    status = models.CharField(max_length=16, choices=ProposalStatus.as_choices(), default=ProposalStatus.RUNNING)
    fault = models.TextField(null=True)
    birth_block_number = utils.BiggerIntField()
    metadata = models.JSONField(null=True)
    metadata_url = models.CharField(max_length=256, null=True)
    metadata_hash = models.CharField(max_length=256, null=True)
    setup_complete = models.BooleanField(default=False)


class ProposalReport(TimestampableMixin):
    reason = models.TextField()
    proposal = models.ForeignKey(Proposal, on_delete=models.CASCADE)


class Vote(TimestampableMixin):
    proposal = models.ForeignKey(Proposal, related_name="votes", on_delete=models.CASCADE)
    voter = models.ForeignKey(Account, related_name="votes", on_delete=models.CASCADE)
    in_favor = models.BooleanField(null=True, db_index=True)
    voting_power = utils.BiggerIntField()  # held tokens at proposal creation


class Block(TimestampableMixin):
    number = utils.BiggerIntField(unique=True, editable=False)
    event_data = models.JSONField(default=dict)
    executed = models.BooleanField(default=False, db_index=True)

    class Meta:
        verbose_name = "Block"
        verbose_name_plural = "Blocks"

    def __str__(self):
        return f"{self.number}"
