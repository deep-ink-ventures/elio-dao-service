from collections import defaultdict
from functools import reduce
from itertools import chain

from django.db.models import Q
from django.utils.timezone import now

from multiclique import models


class MultiCliqueEventHandler:
    topics_to_action = None

    def __init__(self):
        self.topics_to_action = {
            ("GOV", "init"): self._init_multiclique_contract,
            ("GOV", "changed"): self._set_default_threshold,
            ("SIGNER", "added"): self._add_signer,
            ("SIGNER", "removed"): self._rm_signer,
        }

    def _update_transactions(self, txn_kwargs):
        # todo refactor
        pass

    @staticmethod
    def _init_multiclique_contract(event_data: dict[list[dict]], **_):
        """
        Args:
            event_data: event input values by contract_id

        updates MultiCliqueAccount based on event data
        creates(if missing) and attaches MultiCliqueSignatories to the account
        """
        accs = {acc.address: acc for acc in models.MultiCliqueAccount.objects.filter(address__in=event_data.keys())}
        sigs = {}
        for contract_id, events in event_data.items():
            acc = accs[contract_id]
            acc.default_threshold = events[0]["threshold"]
            sigs[contract_id] = [models.MultiCliqueSignatory(address=addr) for addr in events[0]["signers"]]

        if accs:
            models.MultiCliqueAccount.objects.bulk_update(accs.values(), ["default_threshold"])
            models.MultiCliqueSignatory.objects.bulk_create(chain(*sigs.values()), ignore_conflicts=True)
            m2m = models.MultiCliqueAccount.signatories.through
            m2m.objects.bulk_create(
                [
                    m2m(multicliqueaccount_id=addr, multicliquesignatory_id=sig.address)
                    for addr in accs.keys()
                    for sig in sigs[addr]
                ],
                ignore_conflicts=True,
            )

    @staticmethod
    def _add_signer(event_data: dict[list[dict]], **_):
        """
        Args:
            event_data: event input values by contract_id

        creates(if missing) and attaches MultiCliqueSignatories to the account
        """
        acc_to_sigs: defaultdict = defaultdict(list)
        for contract_id, events in event_data.items():
            for event in events:
                acc_to_sigs[contract_id].append(models.MultiCliqueSignatory(address=event["signer"]))

        if acc_to_sigs:
            models.MultiCliqueSignatory.objects.bulk_create(chain(*acc_to_sigs.values()), ignore_conflicts=True)
            models.MultiCliqueTransaction.objects.bulk_create(
                [
                    models.MultiCliqueTransaction(
                        multiclique_account_id=addr, call_func="add_signer", call_args=[sig.address]
                    )
                    for addr, sigs in acc_to_sigs.items()
                    for sig in sigs
                ],
                ignore_conflicts=True,
            )
            models.MultiCliqueTransaction.objects.filter(
                reduce(
                    Q.__or__,
                    [
                        Q(multiclique_account_id=addr, call_func="add_signer", call_args=[sig.address])
                        for addr, sigs in acc_to_sigs.items()
                        for sig in sigs
                    ],
                ),
                executed_at__isnull=True,
            ).update(status=models.TransactionStatus.EXECUTED, executed_at=now())
            m2m = models.MultiCliqueAccount.signatories.through
            m2m.objects.bulk_create(
                [
                    m2m(multicliqueaccount_id=addr, multicliquesignatory_id=sig.address)
                    for addr, sigs in acc_to_sigs.items()
                    for sig in sigs
                ],
                ignore_conflicts=True,
            )

    @staticmethod
    def _rm_signer(event_data: dict[list[dict]], **_):
        """
        Args:
            event_data: event input values by contract_id

        rms(if existing) MultiCliqueSignatories from the account
        """
        acc_to_sigs: defaultdict = defaultdict(list)
        for contract_id, events in event_data.items():
            for event in events:
                acc_to_sigs[contract_id].append(models.MultiCliqueSignatory(address=event["signer"]))

        if acc_to_sigs:
            models.MultiCliqueTransaction.objects.bulk_create(
                [
                    models.MultiCliqueTransaction(
                        multiclique_account_id=addr, call_func="remove_signer", call_args=[sig.address]
                    )
                    for addr, sigs in acc_to_sigs.items()
                    for sig in sigs
                ],
                ignore_conflicts=True,
            )
            models.MultiCliqueTransaction.objects.filter(
                reduce(
                    Q.__or__,
                    [
                        Q(multiclique_account_id=addr, call_func="remove_signer", call_args=[sig.address])
                        for addr, sigs in acc_to_sigs.items()
                        for sig in sigs
                    ],
                ),
                executed_at__isnull=True,
            ).update(status=models.TransactionStatus.EXECUTED, executed_at=now())
            models.MultiCliqueAccount.signatories.through.objects.filter(
                # WHERE (
                #     (multicliqueaccount_id = 1 AND multicliquesignatory_id IN (3, 4))
                #     OR (multicliqueaccount_id = 2 AND multicliquesignatory_id IN (5, 6))
                #     OR ...
                # )
                reduce(
                    Q.__or__,
                    [
                        Q(multicliqueaccount_id=addr, multicliquesignatory_id__in=[sig.address for sig in sigs])
                        for addr, sigs in acc_to_sigs.items()
                    ],
                )
            ).delete()

    @staticmethod
    def _set_default_threshold(event_data: dict[list[dict]], **_):
        """
        Args:
            event_data: event input values by contract_id

        updates MultiCliqueAccount based on event data
        """
        accs = {acc.address: acc for acc in models.MultiCliqueAccount.objects.filter(address__in=event_data.keys())}
        for contract_id, events in event_data.items():
            accs[contract_id].default_threshold = events[0]["threshold"]

        if accs:
            models.MultiCliqueAccount.objects.bulk_update(accs.values(), ["default_threshold"])
            models.MultiCliqueTransaction.objects.bulk_create(
                [
                    models.MultiCliqueTransaction(
                        multiclique_account_id=addr,
                        call_func="set_default_threshold",
                        call_args=[acc.default_threshold],
                    )
                    for addr, acc in accs.items()
                ],
                ignore_conflicts=True,
            )
            models.MultiCliqueTransaction.objects.filter(
                reduce(
                    Q.__or__,
                    [
                        Q(
                            multiclique_account_id=addr,
                            call_func="set_default_threshold",
                            call_args=[acc.default_threshold],
                        )
                        for addr, acc in accs.items()
                    ],
                ),
                executed_at__isnull=True,
            ).update(status=models.TransactionStatus.EXECUTED, executed_at=now())


multiclique_event_handler = MultiCliqueEventHandler()
