"""Publishing risk-scored proposals after a stage completes.

Shared by every analysis job, because the loop -- supersede the stage's stale
advice, write the new proposals, tell the case's subscribers -- must behave
identically no matter which stage produced it. If one job stacked duplicates
while another replaced them, the operator's queue would stop being trustworthy.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from necropsy.contracts.events import Event, EventType, case_channel
from necropsy.contracts.host import HostServices
from necropsy.contracts.risk import ActionProposal
from necropsy.db.models import AnalysisJob, Sample
from necropsy.db.repos import actions as actions_repo


def publish_proposals(
    session: Session,
    host: HostServices,
    job: AnalysisJob,
    sample: Sample | None,
    proposals: list[ActionProposal],
) -> int:
    if not proposals:
        return 0

    actions_repo.supersede_open(session, job.case_id, [p.kind for p in proposals])
    for proposal in proposals:
        action = actions_repo.create_from_proposal(
            session,
            proposal,
            case_id=job.case_id,
            sample_id=sample.id if sample else None,
            origin_job_id=job.id,
        )
        host.publish(
            case_channel(job.case_id),
            Event(
                type=EventType.ACTION_PROPOSED,
                case_id=job.case_id,
                payload={
                    "action_id": action.id,
                    "kind": action.kind,
                    "title": action.title,
                    "risk_score": action.risk_score,
                    "risk_band": action.risk_band,
                    "available": action.available,
                },
            ),
        )
    return len(proposals)
