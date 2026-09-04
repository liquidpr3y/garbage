from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from necropsy.enums import KillChainPhase, Producer, Severity


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    case_id: str
    sample_id: str | None
    job_id: str | None
    producer: Producer
    type: str
    title: str
    description: str | None
    severity: Severity
    confidence: float
    # Populated from Phase 4. Present now so the GUI can bind to the final
    # shape and the heatmap becomes a query rather than a migration.
    attack_technique_ids: list[str] = Field(default_factory=list)
    kill_chain_phase: KillChainPhase | None
    evidence: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
