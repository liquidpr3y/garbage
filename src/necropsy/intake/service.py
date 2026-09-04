"""Sample intake.

Ingest is deliberately narrow: hash the bytes, vault them, attach them to a
case, audit it, and queue identification. Everything analytical happens in the
identify job, which reads back out of the vault -- so the vault read path and
its audit trail are exercised on every single sample rather than only in
Phase 3.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from sqlalchemy.orm import Session

from necropsy.config import get_settings
from necropsy.contracts.events import Event, EventType, case_channel
from necropsy.contracts.host import HostServices
from necropsy.db.models import AuditAction, Sample
from necropsy.db.repos import audit, cases, jobs, samples
from necropsy.enums import JobKind, SampleSource, StorageState
from necropsy.intake.hashing import hash_file
from necropsy.intake.vault import Vault


class IngestError(RuntimeError):
    pass


class SampleTooLarge(IngestError):
    pass


class CaseNotFound(IngestError):
    pass


@dataclass
class IngestResult:
    sample: Sample
    sample_created: bool
    attached: bool
    job_id: str | None
    other_case_count: int


def open_vault(session: Session, *, actor: str, case_id: str | None = None) -> Vault:
    """A vault whose every read and write lands in this session's audit log."""
    settings = get_settings()

    def hook(action: str, detail: dict[str, object]) -> None:
        audit.record(
            session,
            action=action,
            actor=actor,
            case_id=case_id,
            object_type="sample",
            object_id=str(detail.get("sha256") or ""),
            detail=dict(detail),
        )

    return Vault(settings.vault_root, settings.vault_key_bytes(), audit=hook)


def ingest_file(
    session: Session,
    host: HostServices,
    *,
    case_id: str,
    src: Path,
    observed_filename: str | None = None,
    source: SampleSource = SampleSource.UPLOAD,
    note: str | None = None,
    actor: str | None = None,
    enqueue: bool = True,
) -> IngestResult:
    settings = get_settings()
    actor = actor or host.actor()

    case = cases.get(session, case_id)
    if case is None:
        raise CaseNotFound(case_id)

    size = src.stat().st_size
    if size > settings.max_sample_bytes:
        raise SampleTooLarge(f"{size} bytes exceeds cap of {settings.max_sample_bytes}")
    if size == 0:
        raise IngestError("refusing to ingest an empty file")

    hashes = hash_file(src, want_ssdeep=True)
    vault = open_vault(session, actor=actor, case_id=case_id)

    sample = samples.get_by_sha256(session, hashes.sha256)
    sample_created = sample is None

    if sample is None:
        ref = vault.put(src, hashes.sha256, actor=actor)
        sample = samples.create(
            session,
            sha256=hashes.sha256,
            sha1=hashes.sha1,
            md5=hashes.md5,
            tlsh=hashes.tlsh,
            ssdeep=hashes.ssdeep,
            size=hashes.size,
            vault_uri=ref.uri,
            storage_state=StorageState.VAULTED,
        )
    elif not vault.exists(sample.sha256):
        # Metadata survived but the bytes did not -- most likely XProtect. Re-vault
        # rather than leaving a case pointing at nothing.
        ref = vault.put(src, hashes.sha256, actor=actor)
        sample.vault_uri = ref.uri
        sample.storage_state = StorageState.VAULTED

    link, attached = samples.attach_to_case(
        session,
        case_id=case_id,
        sample_id=sample.id,
        observed_filename=observed_filename or src.name,
        source=source,
        submitted_by=actor,
        note=note,
    )

    audit.record(
        session,
        action=AuditAction.SAMPLE_INGESTED if sample_created else AuditAction.SAMPLE_DEDUPED,
        actor=actor,
        case_id=case_id,
        object_type="sample",
        object_id=sample.sha256,
        detail={
            "size": hashes.size,
            "observed_filename": observed_filename or src.name,
            "source": source.value,
            "attached": attached,
        },
    )

    other = samples.other_cases(session, sample.id, exclude_case_id=case_id)

    job_id = None
    if enqueue:
        job, _ = jobs.enqueue_or_get(
            session,
            case_id=case_id,
            kind=JobKind.IDENTIFY,
            sample_id=sample.id,
            sample_sha256=sample.sha256,
        )
        job_id = job.id

    host.publish(
        case_channel(case_id),
        Event(
            type=EventType.SAMPLE_INGESTED,
            case_id=case_id,
            payload={
                "sample_id": sample.id,
                "sha256": sample.sha256,
                "size": sample.size,
                "new_to_platform": sample_created,
                "also_in_cases": len(other),
            },
        ),
    )

    return IngestResult(
        sample=sample,
        sample_created=sample_created,
        attached=attached,
        job_id=job_id,
        other_case_count=len(other),
    )
