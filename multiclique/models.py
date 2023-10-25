from django.db.models import (
    CASCADE,
    DO_NOTHING,
    SET_NULL,
    BigIntegerField,
    CharField,
    DateTimeField,
    ForeignKey,
    JSONField,
    ManyToManyField,
    PositiveIntegerField,
    Q,
    UniqueConstraint,
)

from core.models import TimestampableMixin
from core.utils import BiggerIntField, ChoiceEnum


class MultiCliquePolicy(TimestampableMixin):
    address = CharField(primary_key=True, max_length=128)
    name = CharField(max_length=256, null=True)

    class Meta:
        db_table = "multiclique_policy"
        verbose_name = "MultiClique Policy"
        verbose_name_plural = "MultiClique Policies"


class MultiCliqueContractType(ChoiceEnum):
    ELIO_CORE = "elio core"
    ELIO_VOTES = "elio votes"
    ELIO_ASSET = "elio asset"
    UNKNOWN = "unknown"


class MultiCliqueContract(TimestampableMixin):
    policies = ManyToManyField(MultiCliquePolicy, related_name="contracts")
    address = CharField(primary_key=True, max_length=128)
    limit = BiggerIntField(null=True)
    already_spent = BiggerIntField(null=True)
    type = CharField(
        max_length=32, choices=MultiCliqueContractType.as_choices(), default=MultiCliqueContractType.UNKNOWN
    )

    class Meta:
        db_table = "multiclique_contract"
        verbose_name = "MultiClique Contract"
        verbose_name_plural = "MultiClique Contracts"


class MultiCliqueSignatory(TimestampableMixin):
    address = CharField(primary_key=True, max_length=128)
    name = CharField(max_length=128, null=True)

    class Meta:
        db_table = "multiclique_signatory"
        verbose_name = "MultiClique Signatory"
        verbose_name_plural = "MultiClique Signatories"


class MultiCliqueSignature(TimestampableMixin):
    signatory = ForeignKey(MultiCliqueSignatory, related_name="signatures", on_delete=DO_NOTHING)
    signature = CharField(max_length=256, primary_key=True)

    class Meta:
        db_table = "multiclique_signature"
        verbose_name = "MultiClique Signature"
        verbose_name_plural = "MultiClique Signatures"


class MultiCliqueAccount(TimestampableMixin):
    address = CharField(primary_key=True, max_length=128)
    name = CharField(max_length=128)
    signatories = ManyToManyField(MultiCliqueSignatory, related_name="accounts")
    default_threshold = PositiveIntegerField(null=True)
    policy = ForeignKey(MultiCliquePolicy, related_name="accounts", on_delete=SET_NULL, null=True)

    class Meta:
        db_table = "multiclique_account"
        verbose_name = "MultiClique Account"
        verbose_name_plural = " MultiClique Accounts"


class TransactionStatus(ChoiceEnum):
    PENDING = "pending"
    REJECTED = "rejected"
    EXECUTABLE = "executable"
    EXECUTED = "executed"


class MultiCliqueTransaction(TimestampableMixin):
    xdr = CharField(max_length=4096, null=True)
    nonce = BigIntegerField(null=True)
    ledger = BigIntegerField(null=True)
    preimage_hash = CharField(max_length=1024, null=True)
    call_func = CharField(max_length=256, null=True)
    call_args = JSONField(null=True)
    multiclique_account = ForeignKey(MultiCliqueAccount, related_name="transactions", on_delete=CASCADE)
    submitter = ForeignKey(MultiCliqueSignatory, related_name="submitted_transactions", null=True, on_delete=SET_NULL)
    approvals = ManyToManyField(MultiCliqueSignature, related_name="transaction_approvals")
    rejections = ManyToManyField(MultiCliqueSignature, related_name="transaction_rejections")
    status = CharField(max_length=16, choices=TransactionStatus.as_choices(), default=TransactionStatus.PENDING)
    executed_at = DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "multiclique_transaction"
        verbose_name = "MultiClique Transaction"
        verbose_name_plural = "MultiClique Transactions"
        constraints = [
            UniqueConstraint(
                name="unique_with_optional", fields=["call_func", "call_args", "multiclique_account", "executed_at"]
            ),
            UniqueConstraint(
                name="unique_without_optional",
                fields=["call_func", "call_args", "multiclique_account"],
                condition=Q(executed_at=None),
            ),
        ]
