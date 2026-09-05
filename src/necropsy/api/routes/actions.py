"""Accept or reject the proposals a stage produced.

This endpoint is the human-in-the-loop. Nothing in Necropsy escalates itself:
an analysis stage can only ever *propose* the next one, and it stays inert
until a named operator accepts it. The policy itself lives in
`necropsy.actions.service` so the CLI cannot reach a laxer version of it.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from necropsy.actions.service import ActionRefused, accept, reject
from necropsy.api.deps import db_session, host_services
from necropsy.contracts.host import HostServices
from necropsy.db.repos import actions as actions_repo, cases as cases_repo
from necropsy.enums import ActionState
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

    try:
        acceptance = accept(session, host, action, note=body.note if body else None)
    except ActionRefused as exc:
        raise HTTPException(exc.status, str(exc)) from None

    # Commit before submitting: the worker opens its own session.
    session.commit()
    get_runner().submit(acceptance.job_id, acceptance.kind.value)
    session.expire_all()

    return AcceptResponse(
        action=ActionOut.model_validate(action, from_attributes=True),
        job_id=acceptance.job_id,
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
    try:
        reject(session, host, action, note=body.note if body else None)
    except ActionRefused as exc:
        raise HTTPException(exc.status, str(exc)) from None
    session.commit()
    return action
