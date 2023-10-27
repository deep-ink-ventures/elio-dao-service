from collections import defaultdict
from functools import reduce
from itertools import chain
from typing import Sequence

from django.core.cache import cache
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
            # todo test and enable these once "outside footprint" bug is fixed
            # ("POLICY", "lmt_set"): self._set_spend_limit,
            # ("POLICY", "lmt_reset"): self._reset_spend_limit,
            # ("POLICY", "spent_upd"): self._already_spent_update,
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
    def _identify_contract_address(contract_addr) -> models.MultiCliqueContractType:
        """
        Args:
            contract_addr: contract address to identify

        Returns:
            MultiCliqueContractType

        checks if the contract address is already known to the service and returns a corresponding
        MultiCliqueContractType
        """
        from core.soroban import soroban_service

        config = soroban_service.set_config()
        asset_addrs = cache.get("asset_addresses") or soroban_service.set_asset_addresses()
        return {
            **{asset_addr: models.MultiCliqueContractType.ELIO_ASSET for asset_addr in asset_addrs},
            config["core_contract_address"]: models.MultiCliqueContractType.ELIO_CORE,
            config["votes_contract_address"]: models.MultiCliqueContractType.ELIO_VOTES,
        }.get(contract_addr, models.MultiCliqueContractType.UNKNOWN)

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
            # update accounts' default_threshold, no need to bulk create since the event can only be caught
            # if the account already exists
            models.MultiCliqueAccount.objects.bulk_update(accs.values(), ["default_threshold"])
            # defensively create missing signatories
            models.MultiCliqueSignatory.objects.bulk_create(chain(*sigs.values()), ignore_conflicts=True)
            # populate acc:signatory m2m
            m2m = models.MultiCliqueAccount.signatories.through
            m2m.objects.bulk_create(
                [
                    m2m(multicliqueaccount_id=addr, multicliquesignatory_id=sig.address)
                    for addr in accs.keys()
                    for sig in sigs[addr]
                ],
                ignore_conflicts=True,
            )
            # no transaction to update since don't create one for init

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
            # defensively create missing signatories
            models.MultiCliqueSignatory.objects.bulk_create(chain(*acc_to_sigs.values()), ignore_conflicts=True)
            # populate acc:signatory m2m
            m2m = models.MultiCliqueAccount.signatories.through
            m2m.objects.bulk_create(
                [
                    m2m(multicliqueaccount_id=addr, multicliquesignatory_id=sig.address)
                    for addr, sigs in acc_to_sigs.items()
                    for sig in sigs
                ],
                ignore_conflicts=True,
            )
            # update transactions
            self._update_transactions(
                "add_signer", [{addr: [sig.address]} for addr, sigs in acc_to_sigs.items() for sig in sigs]
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
            # update accounts
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
            # update transactions
            self._update_transactions(
                "remove_signer", [{addr: [sig.address]} for addr, sigs in acc_to_sigs.items() for sig in sigs]
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
            # update accounts' default_threshold, no need to bulk create since the event can only be caught
            # if the account already exists
            models.MultiCliqueAccount.objects.bulk_update(addr_to_acc.values(), ["default_threshold"])
            # update transactions
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
        pol_addr_to_contracts: defaultdict = defaultdict(list)
        for contract_id, events in event_data.items():
            for event in events:
                policy_addr = event["policy"]
                acc_addr_to_pol_addr[contract_id] = event["policy"]
                pol_addr_to_contracts[policy_addr] = [
                    models.MultiCliqueContract(address=ctr_addr, type=self._identify_contract_address(ctr_addr))
                    for ctr_addr in event["context"]
                ]

        if pol_addr_to_contracts:
            # defensively create missing policies
            models.MultiCliquePolicy.objects.bulk_create(
                [models.MultiCliquePolicy(address=addr) for addr in pol_addr_to_contracts.keys()],
                ignore_conflicts=True,
            )
            # add update contract ids so the listener can fetches events for the newly added policies
            soroban_service.set_trusted_contract_ids()
            # create policy contracts
            models.MultiCliqueContract.objects.bulk_create(
                chain(*pol_addr_to_contracts.values()), ignore_conflicts=True
            )
            # populate policy:contact m2m
            m2m_mdl = models.MultiCliqueContract.policies.through
            m2m_mdl.objects.bulk_create(
                [
                    m2m_mdl(multicliquecontract_id=contract.address, multicliquepolicy_id=pol_addr)
                    for pol_addr, contracts in pol_addr_to_contracts.items()
                    for contract in contracts
                ],
                ignore_conflicts=True,
            )
            # update accounts
            for acc in (accs := models.MultiCliqueAccount.objects.filter(address__in=acc_addr_to_pol_addr.keys())):
                acc.policy_id = acc_addr_to_pol_addr[acc.address]
            models.MultiCliqueAccount.objects.bulk_update(accs, fields=["policy_id"])
            # update transactions
            self._update_transactions(
                "attach_policy",
                [
                    {acc_addr: [pol_addr, [ctr.address for ctr in pol_addr_to_contracts[pol_addr]]]}
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
            # delete the detached contracts
            models.MultiCliqueContract.policies.through.objects.filter(
                reduce(
                    Q.__or__,
                    [
                        Q(multicliquepolicy__accounts__address=acc_addr, multicliquecontract_id__in=ctx)
                        for acc_addr, ctx in acc_addr_to_ctx.items()
                    ],
                )
            ).delete()
            # delete all policies which have no attached contracts
            models.MultiCliquePolicy.objects.filter(
                ~Q(
                    address__in=list(
                        models.MultiCliqueContract.policies.through.objects.all().values_list(
                            "multicliquepolicy_id", flat=True
                        )
                    )
                )
            ).delete()
            # update transactions
            self._update_transactions("detach_policy", [{acc_addr: [ctx]} for acc_addr, ctx in acc_addr_to_ctx.items()])

    def _set_spend_limit(self, event_data: dict[list[dict]], **_):
        """
        Args:
            event_data: event input values by contract_id

        sets spend limits for MultiCliqueContracts
        """

        data = {}  # (pol_addr, ctr_addr): (spend_limit, mc_addr)
        for contract_id, events in event_data.items():
            for event in events:
                data[(contract_id, event["contract_address"])] = (
                    event["spend_limit"],
                    event["multiclique_address"],
                )

        if data:
            # update contracts
            ctrs_to_update = []
            for m2m in models.MultiCliqueContract.policies.through.objects.filter(
                reduce(
                    Q.__or__,
                    [
                        Q(multicliquepolicy_id=pol_addr, multicliquecontract_id=ctr_addr)
                        for pol_addr, ctr_addr in data.keys()
                    ],
                )
            ).select_related("multicliquecontract"):
                m2m.contract.limit, _ = data[(m2m.multicliquepolicy_id, m2m.multicliquecontract_id)]
                ctrs_to_update.append(m2m.contract)
            models.MultiCliqueContract.objects.bulk_create(ctrs_to_update, update_fields=["limit"])
            # update transactions
            self._update_transactions(
                "set_spend_limit",
                [{mc_addr: [ctr_addr, spend_limit]} for (_, ctr_addr), (spend_limit, mc_addr) in data.items()],
            )

    def _reset_spend_limit(self, event_data: dict[list[dict]], **_):
        """
        Args:
            event_data: event input values by contract_id

        resets spend limits for MultiCliqueContracts
        """

        data = {}  # (pol_addr, ctr_addr): mc_addr
        for contract_id, events in event_data.items():
            for event in events:
                data[(contract_id, event["contract_address"])] = event["multiclique_address"]

        if data:
            # update contracts
            models.MultiCliqueContract.objects.filter(
                reduce(
                    Q.__or__,
                    [Q(policies__address=pol_addr, address=ctr_addr) for pol_addr, ctr_addr in data.keys()],
                )
            ).update(limit=0)
            # update transactions
            self._update_transactions(
                "reset_spend_limit",
                [{mc_addr: [ctr_addr]} for (_, ctr_addr), mc_addr in data.items()],
            )

    @staticmethod
    def _already_spent_update(event_data: dict[list[dict]], **_):
        """
        Args:
            event_data: event input values by contract_id

        updates already_spent for MultiCliqueContracts
        """
        data = {}  # (pol_addr, ctr_addr): already_spent
        for contract_id, events in event_data.items():
            for event in events:
                data[(contract_id, event["contract_address"])] = event["already_spent"]

        if data:
            # update contracts
            ctrs_to_update = []
            for m2m in models.MultiCliqueContract.policies.through.objects.filter(
                reduce(
                    Q.__or__,
                    [
                        Q(multicliquepolicy_id=pol_addr, multicliquecontract_id=ctr_addr)
                        for pol_addr, ctr_addr in data.keys()
                    ],
                )
            ).select_related("multicliquecontract"):
                m2m.contract.already_spent = data[(m2m.multicliquepolicy_id, m2m.multicliquecontract_id)]
                ctrs_to_update.append(m2m.contract)
            models.MultiCliqueContract.objects.bulk_create(ctrs_to_update, update_fields=["already_spent"])
            # no transactions to update


multiclique_event_handler = MultiCliqueEventHandler()
