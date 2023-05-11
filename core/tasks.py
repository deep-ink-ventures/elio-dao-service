import logging

from celery import shared_task

from core import models

logger = logging.getLogger("alerts")


@shared_task()
def update_dao_metadata(dao_metadata: dict):
    """
    Args:
        dao_metadata: DAO metadata. format: {dao_id: {"metadata_url": metadata_url, "metadata_hash": metadata_hash}}

    Returns:
        None

    fetches all DAOs identified by dao_id in dao_metadata from db.
    for all fetched DAOs:
        - checks if the metadata_hash differs from the metadata_hash provided to the task (dao_metadata)
        - if so download metadata from provided url and updates DAO
    """
    from core.file_handling.file_handler import HashMismatchException, file_handler

    daos = set(models.Dao.objects.filter(id__in=dao_metadata.keys()))
    # update DAOs w/ differing metadata_hash
    for dao in (daos_to_update := {dao for dao in daos if dao.metadata_hash != dao_metadata[dao.id]["metadata_hash"]}):
        metadata_url = dao_metadata[dao.id]["metadata_url"]
        metadata_hash = dao_metadata[dao.id]["metadata_hash"]
        dao.metadata_url = metadata_url
        dao.metadata_hash = metadata_hash
        try:
            dao.metadata = file_handler.download_metadata(url=metadata_url, metadata_hash=metadata_hash)
        except HashMismatchException:
            logger.error("Hash mismatch while fetching DAO metadata from provided url.")
        except Exception:  # noqa E722
            logger.exception("Unexpected error while fetching DAO metadata from provided url.")

    if daos_to_update:
        models.Dao.objects.bulk_update(daos_to_update, fields=["metadata", "metadata_url", "metadata_hash"])


@shared_task()
def update_proposal_metadata(proposal_ids: list):
    """
    Args:
        proposal_ids: ids of Proposal to update metadata for

    Returns:
        None

     fetches and updates Proposal.metadata for the given proposal_ids
    """
    from core.file_handling.file_handler import HashMismatchException, file_handler

    proposals = set(models.Proposal.objects.filter(id__in=proposal_ids))
    proposal_to_update = []
    for proposal in proposals:
        try:
            proposal.metadata = file_handler.download_metadata(
                url=proposal.metadata_url, metadata_hash=proposal.metadata_hash
            )
        except HashMismatchException:
            logger.error("Hash mismatch while fetching Proposal metadata from provided url.")
        except Exception:  # noqa E722
            logger.exception("Unexpected error while fetching Proposal metadata from provided url.")
        else:
            proposal_to_update.append(proposal)
    if proposal_to_update:
        models.Proposal.objects.bulk_update(proposal_to_update, fields=["metadata"])
