from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from necropsy.enums import JobKind, JobState


class JobOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    case_id: str
    sample_id: str | None
    kind: JobKind
    state: JobState
    params: dict[str, Any] = Field(default_factory=dict)
    result_summary: dict[str, Any] = Field(default_factory=dict)
    error: str | None
    worker: str | None
    queued_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
