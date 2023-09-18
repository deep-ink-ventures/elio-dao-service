from django.contrib.postgres.fields import ArrayField
from django.db import models

from core.models import TimestampableMixin
from core.utils import ChoiceEnum


class MultiCliquePolicy(TimestampableMixin):
    name = models.CharField(primary_key=True, max_length=256)
    active = models.BooleanField(default=False)

    class Meta:
        db_table = "multiclique_policies"
        verbose_name = "MultiCliqueAccount Policy"
        verbose_name_plural = "MultiCliqueAccount Policies"


class MultiCliqueAccount(TimestampableMixin):
    address = models.CharField(primary_key=True, max_length=128)
    public_keys = ArrayField(models.CharField(max_length=256), default=list)
    default_threshold = models.PositiveIntegerField(null=True)
    policy = models.ForeignKey(MultiCliquePolicy, on_delete=models.SET_NULL, null=True)

    class Meta:
        db_table = "multiclique_accounts"
        verbose_name = "MultiClique Account"
        verbose_name_plural = " MultiClique Accounts"

    def __str__(self):
        return f"{self.address}"


class TransactionStatus(ChoiceEnum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXECUTED = "executed"


class MultiCliqueTransaction(TimestampableMixin):
    xdr = models.CharField(max_length=1024)
    preimage_hash = models.CharField(max_length=1024)
    call_func = models.CharField(max_length=256, null=True)
    call_args = models.JSONField(null=True)
    multiclique_account = models.ForeignKey(MultiCliqueAccount, related_name="transactions", on_delete=models.CASCADE)
    signers = ArrayField(models.CharField(max_length=256), default=list)
    status = models.CharField(max_length=16, choices=TransactionStatus.as_choices(), default=TransactionStatus.PENDING)
    executed_at = models.DateTimeField(null=True, blank=True)

    # todo find unique id

    class Meta:
        db_table = "multiclique_transactions"
        verbose_name = "MultiCliqueAccount Transaction"
        verbose_name_plural = "MultiCliqueAccount Transactions"

    def __str__(self):
        return f"XDR: {self.xdr[:20]}..."
