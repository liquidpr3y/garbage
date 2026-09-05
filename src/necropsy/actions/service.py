"""Accepting and rejecting proposals.

This is the human-in-the-loop gate, and it is the only route to running a job
that a stage proposed -- including detonation. It lives in a service rather
than in the API route so the CLI cannot reach a different, laxer version of
the same policy: there is one place that decides whether work may start, and
one place that records who authorised it.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy.orm import Session

from necropsy.contracts.host import HostServices
from necropsy.db.models import AuditAction, NextAction
from necropsy.db.repos import actions as actions_repo, audit, cases as cases_repo
from necropsy.db.repos import jobs as jobs_repo, samples as samples_repo
from necropsy.enums import ActionState, JobKind
from necropsy.jobs.registry import NOT_YET_IMPLEMENTED, is_implemented
from necropsy.scoring.proposals import tooling_note


class ActionRefused(RuntimeError):
    """The proposal cannot be accepted, with a reason an operator can act on."""

    def __init__(self, reason: str, *, status: int = 409) -> None:
        self.status = status
        super().__init__(reason)


@dataclass
class Acceptance:
    action: NextAction
    job_id: str
    kind: JobKind


def accept(
    session: Session, host: HostServices, action: NextAction, *, note: str | None = None
) -> Acceptance:
    """Authorise a proposal and queue its job. Does not run it."""
    if action.state is not ActionState.PROPOSED:
        raise ActionRefused(f"action already {action.state.value}")

    try:
        kind = JobKind(action.kind)
    except ValueError:
        raise ActionRefused(f"unknown action kind {action.kind!r}", status=400) from None

    # Policy before capability: "not implemented yet" would send an operator
    # away expecting this to work later, when the real answer is that the case
    # forbids it and always will.
    if kind is JobKind.AI_SUMMARISE:
        case = cases_repo.get(session, action.case_id)
        if case is None or not case.ai_disclosure_allowed:
            raise ActionRefused(
                "this case has ai_disclosure_allowed set to false; sample-derived "
                "content may not be sent to a third-party API",
                status=403,
            )

    if not is_implemented(kind):
        raise ActionRefused(f"{kind.value} is not implemented until {NOT_YET_IMPLEMENTED[kind]}")

    # A proposal can be unavailable for reasons unrelated to implementation --
    # Ghidra missing, no sandbox configured. Re-check live rather than trusting
    # the stored flag: the tool may have been installed since.
    if not action.available:
        reason = tooling_note(kind)
        if reason:
            raise ActionRefused(reason)
        action.available = True
        action.unavailable_reason = None
        session.flush()

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
        session, action, state=ActionState.ACCEPTED, actor=host.actor(),
        note=note, resulting_job_id=job.id,
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
    return Acceptance(action=action, job_id=job.id, kind=kind)


def reject(
    session: Session, host: HostServices, action: NextAction, *, note: str | None = None
) -> NextAction:
    if action.state is not ActionState.PROPOSED:
        raise ActionRefused(f"action already {action.state.value}")

    actions_repo.decide(
        session, action, state=ActionState.REJECTED, actor=host.actor(), note=note
    )
    audit.record(
        session,
        action=AuditAction.ACTION_REJECTED,
        actor=host.actor(),
        case_id=action.case_id,
        object_type="next_action",
        object_id=action.id,
        detail={"kind": action.kind, "note": note},
    )
    return action
