"""Accept or reject the proposals a stage produced.

This endpoint is the human-in-the-loop. Nothing in Necropsy escalates itself:
an analysis stage can only ever *propose* the next one, and it stays inert until
a named operator accepts it. The decision is recorded on the row, which is also
the chain of custody for anything consequential.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from necropsy.api.deps import db_session, host_services
from necropsy.contracts.host import HostServices
from necropsy.db.models import AuditAction
from necropsy.db.repos import actions as actions_repo, audit, cases as cases_repo, jobs as jobs_repo
from necropsy.db.repos import samples as samples_repo
from necropsy.enums import ActionState, JobKind
from necropsy.jobs.registry import NOT_YET_IMPLEMENTED, is_implemented
from necropsy.jobs.runner import get_runner
from necropsy.schemas.action import AcceptResponse, ActionDecision, ActionOut

router = APIRouter(tags=["actions"])


@router.get("/cases/{case_id}/actions", response_model=list[ActionOut])
def list_actions(
    case_id: str,
    state: ActionState | None = ActionState.PROPOSED,
    session: Session = Depends(db_session),
) -> Any:
    if cases_repo.get(session, case_id) is None:
        raise HTTPException(404, "case not found")
    return actions_repo.for_case(session, case_id, state=state)


@router.post("/actions/{action_id}/accept", response_model=AcceptResponse)
def accept_action(
    action_id: str,
    body: ActionDecision | None = None,
    session: Session = Depends(db_session),
    host: HostServices = Depends(host_services),
) -> Any:
    action = actions_repo.get(session, action_id)
    if action is None:
        raise HTTPException(404, "action not found")
    if action.state is not ActionState.PROPOSED:
        raise HTTPException(409, f"action already {action.state.value}")

    try:
        kind = JobKind(action.kind)
    except ValueError:
        raise HTTPException(400, f"unknown action kind {action.kind!r}") from None

    # Policy before capability. "Not implemented yet" would send an operator away
    # expecting this to work in Phase 5, when the real answer is that this case
    # forbids the disclosure and always will.
    if kind is JobKind.AI_SUMMARISE:
        case = cases_repo.get(session, action.case_id)
        if case is None or not case.ai_disclosure_allowed:
            raise HTTPException(
                403,
                "this case has ai_disclosure_allowed set to false; sample-derived content "
                "may not be sent to a third-party API",
            )

    if not is_implemented(kind):
        raise HTTPException(
            409,
            f"{kind.value} is not implemented until {NOT_YET_IMPLEMENTED[kind]}",
        )

    sample = samples_repo.get(session, action.sample_id) if action.sample_id else None
    job, _ = jobs_repo.enqueue_or_get(
        session,
        case_id=action.case_id,
        kind=kind,
        sample_id=action.sample_id,
        sample_sha256=sample.sha256 if sample else None,
        params=action.params,
    )
    actions_repo.decide(
        session,
        action,
        state=ActionState.ACCEPTED,
        actor=host.actor(),
        note=body.note if body else None,
        resulting_job_id=job.id,
    )
    audit.record(
        session,
        action=AuditAction.ACTION_ACCEPTED,
        actor=host.actor(),
        case_id=action.case_id,
        object_type="next_action",
        object_id=action.id,
        detail={"kind": action.kind, "risk_score": action.risk_score, "job_id": job.id},
    )

    # Commit before submitting: the worker opens its own session.
    session.commit()
    get_runner().submit(job.id, kind.value)
    session.expire_all()

    return AcceptResponse(
        action=ActionOut.model_validate(action, from_attributes=True), job_id=job.id
    )


@router.post("/actions/{action_id}/reject", response_model=ActionOut)
def reject_action(
    action_id: str,
    body: ActionDecision | None = None,
    session: Session = Depends(db_session),
    host: HostServices = Depends(host_services),
) -> Any:
    action = actions_repo.get(session, action_id)
    if action is None:
        raise HTTPException(404, "action not found")
    if action.state is not ActionState.PROPOSED:
        raise HTTPException(409, f"action already {action.state.value}")

    actions_repo.decide(
        session,
        action,
        state=ActionState.REJECTED,
        actor=host.actor(),
        note=body.note if body else None,
    )
    audit.record(
        session,
        action=AuditAction.ACTION_REJECTED,
        actor=host.actor(),
        case_id=action.case_id,
        object_type="next_action",
        object_id=action.id,
        detail={"kind": action.kind, "note": body.note if body else None},
    )
    session.commit()
    return action
