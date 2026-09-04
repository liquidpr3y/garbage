"""Event envelope shared with the pentest module.

Workers cannot hold WebSocket connections, so the flow is always:

    worker -> host.publish(channel, event) -> API process subscriber -> WS fan-out -> GUI

Keeping the envelope identical across modules is what lets one GUI event
handler drive both panels.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class EventType(str, Enum):
    CASE_CREATED = "case.created"
    CASE_UPDATED = "case.updated"
    SAMPLE_INGESTED = "sample.ingested"
    JOB_QUEUED = "job.queued"
    JOB_STARTED = "job.started"
    JOB_SUCCEEDED = "job.succeeded"
    JOB_FAILED = "job.failed"
    FINDING_CREATED = "finding.created"
    ACTION_PROPOSED = "action.proposed"
    ACTION_DECIDED = "action.decided"


class Event(BaseModel):
    """One thing that happened, addressed to a case's subscribers."""

    type: EventType
    case_id: str
    at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    payload: dict[str, Any] = Field(default_factory=dict)


def case_channel(case_id: str) -> str:
    """Redis pub/sub channel carrying one case's events."""
    return f"necropsy:case:{case_id}"
