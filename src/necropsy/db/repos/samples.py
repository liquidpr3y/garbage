from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from necropsy.db.models import Case, CaseSample, Sample


def get_by_sha256(session: Session, sha256: str) -> Sample | None:
    return session.scalar(select(Sample).where(Sample.sha256 == sha256))


def get(session: Session, sample_id: str) -> Sample | None:
    return session.get(Sample, sample_id)


def create(session: Session, **kwargs: object) -> Sample:
    sample = Sample(**kwargs)  # type: ignore[arg-type]
    session.add(sample)
    session.flush()
    return sample


def attach_to_case(session: Session, *, case_id: str, sample_id: str, **kwargs: object) -> tuple[CaseSample, bool]:
    """Attach a sample to a case. Returns (row, created)."""
    existing = session.scalar(
        select(CaseSample).where(
            CaseSample.case_id == case_id, CaseSample.sample_id == sample_id
        )
    )
    if existing is not None:
        return existing, False
    link = CaseSample(case_id=case_id, sample_id=sample_id, **kwargs)  # type: ignore[arg-type]
    session.add(link)
    session.flush()
    return link, True


def for_case(session: Session, case_id: str) -> list[CaseSample]:
    stmt = (
        select(CaseSample)
        .where(CaseSample.case_id == case_id)
        .order_by(CaseSample.added_at.desc())
    )
    return list(session.scalars(stmt))


def other_cases(session: Session, sample_id: str, exclude_case_id: str | None = None) -> list[Case]:
    """Every other case this sample appears in -- the cross-case pivot."""
    stmt = (
        select(Case)
        .join(CaseSample, CaseSample.case_id == Case.id)
        .where(CaseSample.sample_id == sample_id)
    )
    if exclude_case_id:
        stmt = stmt.where(Case.id != exclude_case_id)
    return list(session.scalars(stmt))


def with_tlsh(session: Session, exclude_sample_id: str | None = None) -> list[Sample]:
    stmt = select(Sample).where(Sample.tlsh.is_not(None))
    if exclude_sample_id:
        stmt = stmt.where(Sample.id != exclude_sample_id)
    return list(session.scalars(stmt))
