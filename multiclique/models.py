from django.db import models

from core.models import TimestampableMixin
from core.utils import ChoiceEnum


class MultiCliquePolicy(TimestampableMixin):
    address = models.CharField(primary_key=True, max_length=256)
    name = models.CharField(max_length=256)
    active = models.BooleanField(default=False)

    class Meta:
        db_table = "multiclique_policy"
        verbose_name = "MultiClique Policy"
        verbose_name_plural = "MultiClique Policies"


class MultiCliqueSignatory(TimestampableMixin):
    address = models.CharField(primary_key=True, max_length=128)
    name = models.CharField(max_length=128, null=True)

    class Meta:
        db_table = "multiclique_signatory"
        verbose_name = "MultiClique Signatory"
        verbose_name_plural = "MultiClique Signatories"


class MultiCliqueSignature(TimestampableMixin):
    signatory = models.ForeignKey(MultiCliqueSignatory, on_delete=models.DO_NOTHING)
    signature = models.CharField(max_length=256, primary_key=True)

    class Meta:
        db_table = "multiclique_signature"
        verbose_name = "MultiClique Signature"
        verbose_name_plural = "MultiClique Signatures"


class MultiCliqueAccount(TimestampableMixin):
    address = models.CharField(primary_key=True, max_length=128)
    name = models.CharField(max_length=128)
    signatories = models.ManyToManyField(MultiCliqueSignatory, related_name="accounts")
    default_threshold = models.PositiveIntegerField(null=True)
    policy = models.ForeignKey(MultiCliquePolicy, on_delete=models.SET_NULL, null=True)

    class Meta:
        db_table = "multiclique_account"
        verbose_name = "MultiClique Account"
        verbose_name_plural = " MultiClique Accounts"

    def __str__(self):
        return f"{self.address}"


class TransactionStatus(ChoiceEnum):
    PENDING = "pending"
    REJECTED = "rejected"
    EXECUTABLE = "executable"
    EXECUTED = "executed"


class MultiCliqueTransaction(TimestampableMixin):
    xdr = models.CharField(max_length=4096)
    nonce = models.BigIntegerField(null=True)
    ledger = models.BigIntegerField(null=True)
    preimage_hash = models.CharField(max_length=1024, null=True)
    call_func = models.CharField(max_length=256, null=True)
    call_args = models.JSONField(null=True)
    multiclique_account = models.ForeignKey(MultiCliqueAccount, related_name="transactions", on_delete=models.CASCADE)
    approvals = models.ManyToManyField(MultiCliqueSignature, related_name="transaction_approvals")
    rejections = models.ManyToManyField(MultiCliqueSignature, related_name="transaction_rejections")
    status = models.CharField(max_length=16, choices=TransactionStatus.as_choices(), default=TransactionStatus.PENDING)
    executed_at = models.DateTimeField(null=True, blank=True)
    # todo find unique id

    class Meta:
        db_table = "multiclique_transaction"
        verbose_name = "MultiClique Transaction"
        verbose_name_plural = "MultiClique Transactions"

    def __str__(self):
        return f"XDR: {self.xdr[:20]}..."
