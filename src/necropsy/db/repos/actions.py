from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from necropsy.contracts.risk import ActionProposal
from necropsy.db.models import NextAction
from necropsy.enums import ActionState


def create_from_proposal(
    session: Session,
    proposal: ActionProposal,
    *,
    case_id: str,
    sample_id: str | None = None,
    origin_job_id: str | None = None,
) -> NextAction:
    action = NextAction(
        case_id=case_id,
        sample_id=sample_id,
        origin_job_id=origin_job_id,
        kind=proposal.kind,
        title=proposal.title,
        rationale=proposal.rationale,
        risk_score=proposal.risk.value,
        risk_band=proposal.risk.band.value,
        risk_factors=[f.model_dump() for f in proposal.risk.factors],
        estimated_cost_s=proposal.estimated_cost_s,
        params=proposal.params,
        available=proposal.available,
        unavailable_reason=proposal.unavailable_reason,
    )
    session.add(action)
    session.flush()
    return action


def get(session: Session, action_id: str) -> NextAction | None:
    return session.get(NextAction, action_id)


def for_case(
    session: Session, case_id: str, *, state: ActionState | None = ActionState.PROPOSED
) -> list[NextAction]:
    stmt = select(NextAction).where(NextAction.case_id == case_id)
    if state is not None:
        stmt = stmt.where(NextAction.state == state)
    return list(session.scalars(stmt.order_by(NextAction.risk_score.desc())))


def decide(
    session: Session,
    action: NextAction,
    *,
    state: ActionState,
    actor: str,
    note: str | None = None,
    resulting_job_id: str | None = None,
) -> NextAction:
    action.state = state
    action.decided_by = actor
    action.decided_at = datetime.now(timezone.utc)
    action.decision_note = note
    if resulting_job_id:
        action.resulting_job_id = resulting_job_id
    session.flush()
    return action


def supersede_open(session: Session, case_id: str, kinds: list[str]) -> int:
    """Expire stale open proposals of the given kinds.

    Re-running a stage should replace its old advice, not stack a second copy of
    it on the operator's queue.
    """
    stmt = select(NextAction).where(
        NextAction.case_id == case_id,
        NextAction.state == ActionState.PROPOSED,
        NextAction.kind.in_(kinds),
    )
    rows = list(session.scalars(stmt))
    for row in rows:
        row.state = ActionState.EXPIRED
    session.flush()
    return len(rows)
