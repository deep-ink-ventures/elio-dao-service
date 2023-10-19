from collections import defaultdict
from functools import reduce
from itertools import chain
from typing import Optional, Sequence

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
            ("POLICY", "added"): self._add_policy,
            ("POLICY", "removed"): self._rm_policy,
        }

    @staticmethod
    def _update_transactions(call_func: str, acc_to_args: Sequence[dict]):
        models.MultiCliqueTransaction.objects.bulk_create(
            [
                models.MultiCliqueTransaction(multiclique_account_id=acc_addr, call_func=call_func, call_args=args)
                for entry in acc_to_args
                for acc_addr, args in entry.items()
            ],
            ignore_conflicts=True,
        )
        models.MultiCliqueTransaction.objects.filter(
            # WHERE (
            #     (multiclique_account_id = 1 AND call_func = 2 and call_args = [3])
            #     OR (multiclique_account_id = 4 AND call_func = 2 and call_args = [5])
            #     OR ...
            # )
            reduce(
                Q.__or__,
                [
                    Q(multiclique_account_id=acc_addr, call_func=call_func, call_args=args)
                    for entry in acc_to_args
                    for acc_addr, args in entry.items()
                ],
            ),
            executed_at__isnull=True,
        ).update(status=models.TransactionStatus.EXECUTED, executed_at=now())

    @staticmethod
    def _init_multiclique_contract(event_data: dict[list[dict]], **_):
        """
        Args:
            event_data: event input values by contract_id

        updates MultiCliqueAccounts based on event data
        creates(if missing) and attaches MultiCliqueSignatories to MultiCliqueAccounts
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

    def _add_signer(self, event_data: dict[list[dict]], **_):
        """
        Args:
            event_data: event input values by contract_id

        creates(if missing) and attaches MultiCliqueSignatories to MultiCliqueAccounts
        """
        acc_to_sigs: defaultdict = defaultdict(list)
        for contract_id, events in event_data.items():
            for event in events:
                acc_to_sigs[contract_id].append(models.MultiCliqueSignatory(address=event["signer"]))

        if acc_to_sigs:
            models.MultiCliqueSignatory.objects.bulk_create(chain(*acc_to_sigs.values()), ignore_conflicts=True)
            m2m = models.MultiCliqueAccount.signatories.through
            m2m.objects.bulk_create(
                [
                    m2m(multicliqueaccount_id=addr, multicliquesignatory_id=sig.address)
                    for addr, sigs in acc_to_sigs.items()
                    for sig in sigs
                ],
                ignore_conflicts=True,
            )
            self._update_transactions(
                "add_signer", [{addr: [sig]} for addr, sigs in acc_to_sigs.items() for sig in sigs]
            )

    def _rm_signer(self, event_data: dict[list[dict]], **_):
        """
        Args:
            event_data: event input values by contract_id

        rms(if existing) MultiCliqueSignatories from MultiCliqueAccounts
        """
        acc_to_sigs: defaultdict = defaultdict(list)
        for contract_id, events in event_data.items():
            for event in events:
                acc_to_sigs[contract_id].append(models.MultiCliqueSignatory(address=event["signer"]))

        if acc_to_sigs:
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
            self._update_transactions(
                "remove_signer", [{addr: [sig]} for addr, sigs in acc_to_sigs.items() for sig in sigs]
            )

    def _set_default_threshold(self, event_data: dict[list[dict]], **_):
        """
        Args:
            event_data: event input values by contract_id

        updates MultiCliqueAccounts based on event data
        """
        addr_to_acc = {
            acc.address: acc for acc in models.MultiCliqueAccount.objects.filter(address__in=event_data.keys())
        }
        for contract_id, events in event_data.items():
            addr_to_acc[contract_id].default_threshold = events[0]["threshold"]

        if addr_to_acc:
            models.MultiCliqueAccount.objects.bulk_update(addr_to_acc.values(), ["default_threshold"])
            self._update_transactions(
                "set_default_threshold", [{addr: [acc.default_threshold]} for addr, acc in addr_to_acc.items()]
            )

    def _add_policy(self, event_data: dict[list[dict]], **_):
        """
        Args:
            event_data: event input values by contract_id

        creates / updates and attaches MultiCliquePolicies to MultiCliqueAccounts
        """
        from core.soroban import soroban_service

        acc_addr_to_pol_addr = {}
        pol_addr_to_ctx: defaultdict = defaultdict(list)
        for contract_id, events in event_data.items():
            for event in events:
                acc_addr_to_pol_addr[contract_id] = event["policy"]
                pol_addr_to_ctx[event["policy"]].extend(event["context"])

        if pol_addr_to_ctx:
            # update existing policies
            for policy in (
                policies := models.MultiCliquePolicy.objects.filter(address__in=set(acc_addr_to_pol_addr.values()))
            ):
                policy.context.extend(pol_addr_to_ctx.pop(policy.address))

            models.MultiCliquePolicy.objects.bulk_update(policies, fields=["context"])
            # create remaining policies
            if pol_addr_to_ctx:
                models.MultiCliquePolicy.objects.bulk_create(
                    [models.MultiCliquePolicy(address=addr, context=ctx) for addr, ctx in pol_addr_to_ctx.items()],
                    ignore_conflicts=True,
                )
                soroban_service.set_trusted_contract_ids()

            # update accounts
            for acc in (accs := models.MultiCliqueAccount.objects.filter(address__in=acc_addr_to_pol_addr.keys())):
                acc.policy_id = acc_addr_to_pol_addr[acc.address]
            models.MultiCliqueAccount.objects.bulk_update(accs, fields=["policy_id"])
            self._update_transactions(
                "attach_policy",
                [
                    {acc_addr: [pol_addr, *pol_addr_to_ctx[pol_addr]]}
                    for acc_addr, pol_addr in acc_addr_to_pol_addr.items()
                ],
            )

    def _rm_policy(self, event_data: dict[list[dict]], **_):
        """
        Args:
            event_data: event input values by contract_id

        detaches MultiCliquePolicies from MultiCliqueAccounts
        """
        acc_addr_to_ctx: defaultdict = defaultdict(list)
        for contract_id, events in event_data.items():
            for event in events:
                acc_addr_to_ctx[contract_id].extend(event["context"])

        if acc_addr_to_ctx:
            # update existing policies
            accs_to_update = []
            policies_to_update = []
            for acc in models.MultiCliqueAccount.objects.filter(address__in=acc_addr_to_ctx.keys()).select_related(
                "policy"
            ):
                policy: Optional[models.MultiCliquePolicy] = acc.policy
                # set policy's ctx to existing addresses which have not been rmed
                policy.context = [addr for addr in policy.context if addr not in acc_addr_to_ctx[acc.address]]
                policies_to_update.append(policy)
                # if there are no addresses remaining we unlink the policy from the acc
                if not policy.context:
                    acc.policy = None
                    accs_to_update.append(acc)

            models.MultiCliquePolicy.objects.bulk_update(policies_to_update, fields=["context"])
            # update accounts
            if accs_to_update:
                models.MultiCliqueAccount.objects.bulk_update(accs_to_update, fields=["policy"])

            self._update_transactions("detach_policy", [{acc_addr: ctx} for acc_addr, ctx in acc_addr_to_ctx.items()])


multiclique_event_handler = MultiCliqueEventHandler()
