from django.contrib.postgres.fields import ArrayField
from django.db import models, transaction
from django.db.models import Q, UniqueConstraint

from core.models import Account, Asset, Dao, Proposal, TimestampableMixin
from core.utils import ChoiceEnum


class MultiSigQuerySet(models.QuerySet):
    def bulk_create(
        self,
        objs,
        batch_size=None,
        ignore_conflicts=False,
        update_conflicts=False,
        update_fields=None,
        unique_fields=None,
    ):
        if not objs:
            return objs

        # gracefully create Accounts
        Account.objects.bulk_create(
            [Account(address=obj.address or obj.account_ptr_id) for obj in objs], ignore_conflicts=True
        )
        if batch_size is not None and batch_size <= 0:
            raise ValueError("Batch size must be a positive integer.")

        opts = self.model._meta
        if unique_fields:
            # Primary key is allowed in unique_fields.
            unique_fields = [
                self.model._meta.get_field(opts.pk.name if name == "pk" else name) for name in unique_fields
            ]
        if update_fields:
            update_fields = [self.model._meta.get_field(name) for name in update_fields]
        on_conflict = self._check_bulk_create_options(ignore_conflicts, update_conflicts, update_fields, unique_fields)
        self._for_write = True
        ignored_fields = ("created_at", "updated_at", "address")
        fields = [field for field in opts.concrete_fields if field.attname not in ignored_fields]
        objs = list(objs)
        self._prepare_for_bulk_create(objs)
        with transaction.atomic(using=self.db, savepoint=False):
            self._batched_insert(
                objs,
                fields,
                batch_size,
                on_conflict=on_conflict,
                update_fields=update_fields,
                unique_fields=unique_fields,
            )
            for obj_with_pk in objs:
                obj_with_pk._state.adding = False
                obj_with_pk._state.db = self.db
        return objs


class MultiSig(Account):
    objects = MultiSigQuerySet.as_manager()
    signatories = ArrayField(models.CharField(max_length=256), default=list)
    threshold = models.PositiveIntegerField(null=True)
    # denormalizations
    dao = models.ForeignKey(Dao, null=True, on_delete=models.SET_NULL)

    class Meta:
        verbose_name = "MultiSig Account"
        verbose_name_plural = " MultiSig Accounts"

    def __str__(self):
        return f"{self.address}"


class TransactionStatus(ChoiceEnum):
    PENDING = "pending"
    APPROVED = "approved"
    EXECUTED = "executed"


class MultiSigTransaction(TimestampableMixin):
    multisig = models.ForeignKey(MultiSig, related_name="transactions", on_delete=models.CASCADE)
    call = models.JSONField(null=True)
    approvers = ArrayField(models.CharField(max_length=256), default=list)
    status = models.CharField(max_length=16, choices=TransactionStatus.as_choices(), default=TransactionStatus.PENDING)
    executed_at = models.DateTimeField(null=True, blank=True)
    canceled_by = models.CharField(max_length=256, null=True)
    # denormalizations
    call_hash = models.CharField(max_length=256)
    call_data = models.CharField(max_length=1024, null=True)
    call_function = models.CharField(max_length=256, null=True)
    timepoint = models.JSONField(null=True)
    asset = models.ForeignKey(Asset, related_name="transactions", null=True, on_delete=models.SET_NULL)
    dao = models.ForeignKey(Dao, related_name="transactions", null=True, on_delete=models.SET_NULL)
    proposal = models.ForeignKey(Proposal, related_name="transactions", null=True, on_delete=models.SET_NULL)

    class Meta:
        db_table = "multiclique_multisig_transactions"
        verbose_name = "MultiSigTransaction"
        verbose_name_plural = "MultiSigTransactions"
        constraints = [
            UniqueConstraint(name="unique_with_optional", fields=["call_hash", "multisig", "executed_at"]),
            UniqueConstraint(
                name="unique_without_optional", fields=["call_hash", "multisig"], condition=Q(executed_at=None)
            ),
        ]

    @property
    def last_approver(self):
        return self.approvers and self.approvers[-1] or None

    def __str__(self):
        return f"{self.call_hash} | {self.multisig} | {self.executed_at}"
