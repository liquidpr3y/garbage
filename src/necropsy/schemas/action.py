from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from necropsy.enums import ActionState


class ActionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    case_id: str
    sample_id: str | None
    origin_job_id: str | None
    kind: str
    title: str
    rationale: str
    risk_score: float
    risk_band: str
    risk_factors: list[dict[str, Any]] = Field(default_factory=list)
    estimated_cost_s: int | None
    params: dict[str, Any] = Field(default_factory=dict)
    available: bool
    unavailable_reason: str | None
    state: ActionState
    decided_by: str | None
    decided_at: datetime | None
    # The operator's stated reason is the part of the record worth reading back.
    decision_note: str | None
    resulting_job_id: str | None
    created_at: datetime


class ActionDecision(BaseModel):
    note: str | None = None


class AcceptResponse(BaseModel):
    action: ActionOut
    job_id: str | None
