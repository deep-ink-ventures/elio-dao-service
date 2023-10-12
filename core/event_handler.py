import collections
import logging
from functools import partial, reduce
from itertools import chain
from typing import DefaultDict

from django.core.cache import cache
from django.db import IntegrityError, transaction
from django.db.models import Q

from core import models, tasks

logger = logging.getLogger("alerts")
slack_logger = logging.getLogger("alerts.slack")


class ParseBlockException(Exception):
    pass


class SorobanEventHandler:
    topics_to_action = None

    def __init__(self):
        from multiclique.event_handler import multiclique_event_handler

        self.topics_to_action = {
            ("DAO", "created"): self._create_daos,
            ("DAO", "destroyed"): self._delete_daos,
            ("DAO", "new_owner"): self._transfer_dao_ownerships,
            ("DAO", "meta_set"): self._set_dao_metadata,
            ("ASSET", "created"): self._create_assets,
            ("ASSET", "minted"): self._mint_tokens,
            ("ASSET", "transfer"): self._transfer_assets,
            ("PROPOSAL", "conf_set"): self._dao_set_governances,
            ("PROPOSAL", "created"): self._create_proposals,
            ("PROPOSAL", "meta_set"): self._set_proposal_metadata,
            ("PROPOSAL", "vote_cast"): self._register_votes,
            ("PROPOSAL", "state_upd"): self._update_proposal_status,
            ("PROPOSAL", "faulted"): self._fault_proposals,
            **multiclique_event_handler.topics_to_action,
        }

    @staticmethod
    def _create_daos(event_data: dict[list[dict]], **_):
        """
        Args:
            event_data: event input values by contract_id

        creates Daos based on event data
        """
        daos = []
        accs = set()
        for contract_id, events in event_data.items():
            for values in events:
                accs.add(models.Account(address=values["owner_id"]))
                daos.append(
                    models.Dao(
                        id=values["dao_id"],
                        name=values["dao_name"],
                        creator_id=values["owner_id"],
                        owner_id=values["owner_id"],
                        contract_id=contract_id,
                    )
                )
        if daos:
            models.Account.objects.bulk_create(accs, ignore_conflicts=True)
            models.Dao.objects.bulk_create(daos)

    @staticmethod
    def _delete_daos(event_data: dict[list[dict]], **_):
        """
        Args:
            event_data: event input values by contract_id

        deletes Daos based on event data
        """
        if dao_ids := [values["dao_id"] for values in chain(*event_data.values())]:
            models.Dao.objects.filter(id__in=dao_ids).delete()

    @staticmethod
    def _transfer_dao_ownerships(event_data: dict[list[dict]], **_):
        """
        Args:
            event_data: event input values by contract_id

        transfers ownerships of a Daos to new Accounts based on event data
        """
        dao_id_to_new_owner_id = {values["dao_id"]: values["new_owner_id"] for values in chain(*event_data.values())}
        for dao in (daos := list(models.Dao.objects.filter(id__in=dao_id_to_new_owner_id.keys()))):
            dao.owner_id = dao_id_to_new_owner_id[dao.id]
            dao.setup_complete = True

        if daos:
            models.Account.objects.bulk_create(
                [models.Account(address=address) for address in dao_id_to_new_owner_id.values()],
                ignore_conflicts=True,
            )
            models.Dao.objects.bulk_update(daos, ["owner_id", "setup_complete"])

    @staticmethod
    def _set_dao_metadata(event_data: dict[list[dict]], **_):
        """
        Args:
            event_data: event input values by contract_id

        updates Daos' metadata_url and metadata_hash based on event data
        """
        if dao_metadata := {
            values["dao_id"]: {"metadata_url": values["url"], "metadata_hash": values["hash"]}
            for values in chain(*event_data.values())
        }:
            tasks.update_dao_metadata.delay(dao_metadata=dao_metadata)

    @staticmethod
    def _create_assets(event_data: dict[list[dict]], **_):
        """
        Args:
            event_data: event input values by contract_id

        creates Assets based on event data
        """
        from core.soroban import soroban_service

        # create Assets and assign to Daos
        assets = []
        asset_holdings = []
        for values in chain(*event_data.values()):
            asset_id, owner_id, dao_id = (
                values["asset_id"],
                values["owner_id"],
                values["dao_id"],
            )
            assets.append(
                models.Asset(
                    address=asset_id,
                    dao_id=dao_id,
                    owner_id=owner_id,
                    total_supply=0,
                )
            )
            asset_holdings.append(models.AssetHolding(asset_id=asset_id, owner_id=owner_id, balance=0))
        if assets:
            for asset_holding_obj, asset in zip(asset_holdings, models.Asset.objects.bulk_create(assets)):
                asset_holding_obj.asset_id = asset.address
            models.AssetHolding.objects.bulk_create(asset_holdings)
            soroban_service.set_trusted_contract_ids()

    @staticmethod
    def _mint_tokens(event_data: dict[list[dict]], **_):
        """
        Args:
            event_data: event input values by contract_id

        sets Assets and Asset Holdings total_supply / (initial) balance based on event data
        """
        # there is only one data entry (amount, owner_id) per asset
        data = {asset_id: data[0] for asset_id, data in event_data.items()}
        for asset in (assets := models.Asset.objects.filter(address__in=data.keys())):
            asset.total_supply = data[asset.address]["amount"]

        for asset_holding in (asset_holdings := models.AssetHolding.objects.filter(asset_id__in=data.keys())):
            asset_holding_data = data[asset_holding.asset_id]
            asset_holding.balance = asset_holding_data["amount"]

        if assets:
            models.Asset.objects.bulk_update(assets, ["total_supply"])
        if asset_holdings:
            models.AssetHolding.objects.bulk_update(asset_holdings, ["balance"])

    @staticmethod
    def _transfer_assets(event_data: dict[list[dict]], **_):
        """
        Args:
            event_data: event input values by contract_id

        transfers Assets based on event data
        rephrase: transfers ownership of an amount of tokens (models.AssetHolding) from one Account to another
        """
        asset_holding_data = []  # [(asset_id, amount, from_acc, to_acc), ...]
        asset_addrs_to_owner_ids: DefaultDict = collections.defaultdict(set)  # {1 (asset_id): {1, 2, 3} (owner_ids)...}
        asset_address: str
        accs = set()
        # contract_id becomes asset_id
        for asset_address, transfers in event_data.items():
            for transfer in transfers:
                amount, from_acc, to_acc = transfer["amount"], transfer["owner_id"], transfer["new_owner_id"]
                asset_holding_data.append((asset_address, amount, from_acc, to_acc))
                asset_addrs_to_owner_ids[asset_address].add(from_acc)
                asset_addrs_to_owner_ids[asset_address].add(to_acc)
                accs.add(models.Account(address=to_acc))
        if asset_holding_data:
            models.Dao.objects.filter(asset__in=asset_addrs_to_owner_ids.keys(), setup_complete=False).update(
                setup_complete=True
            )
            models.Account.objects.bulk_create(accs, ignore_conflicts=True)
            existing_holdings = collections.defaultdict(dict)
            for asset_holding in models.AssetHolding.objects.filter(
                # WHERE (
                #     (asset_holding.asset_id = 1 AND asset_holding.owner_id IN (1, 2))
                #     OR (asset_holding.asset_id = 2 AND asset_holding.owner_id IN (3, 4))
                #     OR ...
                # )
                reduce(
                    Q.__or__,
                    [
                        Q(asset_id=asset_id, owner_id__in=owner_ids)
                        for asset_id, owner_ids in asset_addrs_to_owner_ids.items()
                    ],
                )
            ):
                existing_holdings[asset_holding.asset_id][asset_holding.owner_id] = asset_holding

            asset_holdings_to_create = {}
            for asset_address, amount, from_acc, to_acc in asset_holding_data:
                # subtract transferred amount from existing models.AssetHolding
                existing_holdings[asset_address][from_acc].balance -= amount

                #  add transferred amount if models.AssetHolding already exists
                if to_acc_holding := asset_holdings_to_create.get((asset_address, to_acc)):
                    to_acc_holding.balance += amount
                elif to_acc_holding := existing_holdings.get(asset_address, {}).get(to_acc):
                    to_acc_holding.balance += amount
                # otherwise create a new models.AssetHolding with balance = transferred amount
                else:
                    asset_holdings_to_create[(asset_address, to_acc)] = models.AssetHolding(
                        owner_id=to_acc, asset_id=asset_address, balance=amount
                    )
            models.AssetHolding.objects.bulk_update(
                [holding for acc_to_holding in existing_holdings.values() for holding in acc_to_holding.values()],
                ["balance"],
            )
            models.AssetHolding.objects.bulk_create(asset_holdings_to_create.values())

    @staticmethod
    def _dao_set_governances(event_data: dict[list[dict]], **_):
        """
        Args:
            event_data: event input values by contract_id

        updates Daos' governance based on event data
        """
        governances = []
        dao_ids = set()
        for values in chain(*event_data.values()):
            dao_ids.add(values["dao_id"])
            governances.append(
                models.Governance(
                    dao_id=values["dao_id"],
                    proposal_duration=values["proposal_duration"],
                    proposal_token_deposit=values.get("proposal_token_deposit"),
                    min_threshold_configuration=values["min_threshold_configuration"],
                    type={"MAJORITY": models.GovernanceType.MAJORITY_VOTE}.get(
                        (proposal_voting_type := values.get("proposal_voting_type")) and proposal_voting_type[0]
                    ),
                )
            )

        if governances:
            models.Governance.objects.filter(dao_id__in=dao_ids).delete()
            models.Governance.objects.bulk_create(governances)

    @staticmethod
    def _create_proposals(event_data: dict[list[dict]], block: models.Block, **_):
        """
        Args:
            event_data: event input values by contract_id
            block: Block the events were extracted from

        create Proposals based on event data
        """
        acc_ids = set()
        dao_ids = set()
        proposals = []
        for values in chain(*event_data.values()):
            acc_ids.add(values["owner_id"])
            dao_ids.add(values["dao_id"])
            proposals.append(
                models.Proposal(
                    id=str(values["proposal_id"]),
                    dao_id=values["dao_id"],
                    creator_id=values["owner_id"],
                    birth_block_number=block.number,
                )
            )
        if proposals:
            # gracefully create potentially missing accounts and corresponding asset holdings for each proposal
            models.Account.objects.bulk_create(
                [models.Account(address=acc_id) for acc_id in acc_ids], ignore_conflicts=True
            )
            dao_id_to_asset_addr = {
                vals["dao_id"]: vals["address"]
                for vals in models.Asset.objects.filter(dao_id__in=dao_ids).values("address", "dao_id")
            }
            models.AssetHolding.objects.bulk_create(
                [
                    models.AssetHolding(
                        owner_id=proposal.creator_id, asset_id=dao_id_to_asset_addr[proposal.dao_id], balance=0
                    )
                    for proposal in proposals
                ],
                ignore_conflicts=True,
            )

            dao_id_to_holding_data: DefaultDict = collections.defaultdict(list)
            for dao_id, owner_id, balance in models.AssetHolding.objects.filter(asset__dao__id__in=dao_ids).values_list(
                "asset__dao_id", "owner_id", "balance"
            ):
                dao_id_to_holding_data[dao_id].append((owner_id, balance))

            models.Proposal.objects.bulk_create(proposals)
            # for all proposals: create a Vote placeholder for each Account holding tokens (AssetHoldings) of the
            # corresponding Dao to keep track of the Account's voting power at the time of Proposal creation.
            models.Vote.objects.bulk_create(
                [
                    models.Vote(proposal_id=proposal.id, voter_id=voter_id, voting_power=balance)
                    for proposal in proposals
                    for voter_id, balance in dao_id_to_holding_data[proposal.dao_id]
                ]
            )

    @staticmethod
    def _set_proposal_metadata(event_data: dict[list[dict]], **_):
        """
         Args:
            event_data: event input values by contract_id

        set Proposals' metadata based on event data
        """
        if proposal_data := {
            str(values["proposal_id"]): (values["url"], values["hash"]) for values in chain(*event_data.values())
        }:
            for proposal in (proposals := models.Proposal.objects.filter(id__in=proposal_data.keys())):
                proposal.metadata_url, proposal.metadata_hash = proposal_data[proposal.id]
                proposal.setup_complete = True
            models.Proposal.objects.bulk_update(proposals, fields=["metadata_hash", "metadata_url", "setup_complete"])
            tasks.update_proposal_metadata.delay(proposal_ids=list(proposal_data.keys()))

    @staticmethod
    def _register_votes(event_data: dict[list[dict]], **_):
        """
         Args:
            event_data: event input values by contract_id

        register Votes based on event data
        """
        proposal_ids_to_voting_data = collections.defaultdict(dict)  # {proposal_id: {voter_id: in_favor}}
        for values in chain(*event_data.values()):
            proposal_ids_to_voting_data[str(values["proposal_id"])][values["voter_id"]] = values["in_favor"]
        if proposal_ids_to_voting_data:
            for vote in (
                votes_to_update := models.Vote.objects.filter(
                    # WHERE (
                    #     (vote.proposal_id = 1 AND vote.voter_id IN (1, 2))
                    #     OR (vote.proposal_id = 2 AND vote.voter_id IN (3, 4))
                    #     OR ...
                    # )
                    reduce(
                        Q.__or__,
                        [
                            Q(proposal_id=proposal_id, voter_id__in=voting_data.keys())
                            for proposal_id, voting_data in proposal_ids_to_voting_data.items()
                        ],
                    )
                )
            ):
                vote.in_favor = proposal_ids_to_voting_data[vote.proposal_id][vote.voter_id]
            models.Vote.objects.bulk_update(votes_to_update, ["in_favor"])

    @staticmethod
    def _update_proposal_status(event_data: dict[list[dict]], **_):
        """
         Args:
            event_data: event input values by contract_id

        updates Proposals status based on event data
        """
        proposal_id_to_status = {}
        for values in chain(*event_data.values()):
            proposal_id_to_status[str(values["proposal_id"])] = {
                "Accepted": models.ProposalStatus.PENDING,
                "Rejected": models.ProposalStatus.REJECTED,
                "Implemented": models.ProposalStatus.IMPLEMENTED,
            }.get(values["status"][0])
        for proposal in (proposals := models.Proposal.objects.filter(id__in=proposal_id_to_status.keys())):
            proposal.status = proposal_id_to_status[proposal.id]
        if proposals:
            models.Proposal.objects.bulk_update(proposals, ["status"])

    @staticmethod
    def _fault_proposals(event_data: dict[list[dict]], **_):
        """
         Args:
            event_data: event input values by contract_id

        faults Proposals' based on event data
        """
        if faulted_proposals := {
            str(values["proposal_id"]): values["reason"] for values in chain(*event_data.values())
        }:
            for proposal in (proposals := models.Proposal.objects.filter(id__in=faulted_proposals.keys())):
                proposal.fault = faulted_proposals[proposal.id]
                proposal.status = models.ProposalStatus.FAULTED
            models.Proposal.objects.bulk_update(proposals, ("fault", "status"))

    @transaction.atomic
    def execute_actions(self, block: models.Block):
        """
        Args:
             block: Block to execute

         alters db's blockchain representation based on the Block's event data
        """
        error_base = f" during block execution. Block number: {block.number}."
        # {topics: {contract_id: [event_data]}}
        event_data_by_topics: DefaultDict = collections.defaultdict(partial(collections.defaultdict, list))
        logger.info(f"Executing event_data... Block number: {block.number}")
        for event in block.event_data:
            contract_id, event_id, topics, vals = event
            logger.info(f"Contract ID: {contract_id} | Event ID: {event_id} | Topics: {topics} | Values: {vals}")
            formatted_topics = tuple(tuple(topic) if isinstance(topic, list) else topic for topic in topics)
            event_data_by_topics[formatted_topics][contract_id].append(vals)

        for topics, events_by_contract_id in event_data_by_topics.items():
            try:
                topics = topics[0], topics[1]
                action = self.topics_to_action[topics]
            except Exception:  # noqa E722
                if not topics[0] in ("fn_call", "fn_return"):
                    logger.error(f"NotImplementedError{error_base} No action defined for topics: {topics}.")
            else:
                try:
                    action(event_data=events_by_contract_id, block=block)
                except IntegrityError:
                    msg = "IntegrityError" + error_base
                    slack_logger.exception(msg)
                    raise ParseBlockException(msg)
                except Exception:  # noqa E722
                    msg = "Unexpected error" + error_base
                    slack_logger.exception(msg)
                    raise ParseBlockException(msg)

        block.executed = True
        block.save(update_fields=["executed"])
        cache.set(key="current_block_number", value=block.number)


soroban_event_handler = SorobanEventHandler()
