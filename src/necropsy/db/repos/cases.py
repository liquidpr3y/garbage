from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from necropsy.db.models import AnalysisJob, Case, CaseSample, Finding, NextAction
from necropsy.enums import ActionState, CaseStatus


def create(session: Session, **kwargs: object) -> Case:
    case = Case(**kwargs)  # type: ignore[arg-type]
    session.add(case)
    session.flush()
    return case


def get(session: Session, case_id: str) -> Case | None:
    return session.get(Case, case_id)


def list_cases(
    session: Session,
    *,
    status: CaseStatus | None = None,
    tag: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[Case]:
    stmt = select(Case).order_by(Case.updated_at.desc())
    if status is not None:
        stmt = stmt.where(Case.status == status)
    rows = list(session.scalars(stmt.limit(limit).offset(offset)))
    if tag is not None:
        # Tags are a JSON list; filtering in Python is honest at POC volume and
        # avoids a dialect-specific JSON query we would have to redo on Postgres.
        rows = [r for r in rows if tag in (r.tags or [])]
    return rows


def counts(session: Session, case_id: str) -> dict[str, int]:
    def _count(model, *where) -> int:  # type: ignore[no-untyped-def]
        stmt = select(func.count()).select_from(model).where(*where)
        return int(session.scalar(stmt) or 0)

    return {
        "samples": _count(CaseSample, CaseSample.case_id == case_id),
        "jobs": _count(AnalysisJob, AnalysisJob.case_id == case_id),
        "findings": _count(Finding, Finding.case_id == case_id),
        "open_actions": _count(
            NextAction,
            NextAction.case_id == case_id,
            NextAction.state == ActionState.PROPOSED,
        ),
    }
