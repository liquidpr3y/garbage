from __future__ import annotations

from pydantic import BaseModel, Field


class TechniqueOut(BaseModel):
    id: str
    name: str
    tactics: list[str] = Field(default_factory=list)
    is_subtechnique: bool
    parent: str | None
    platforms: list[str] = Field(default_factory=list)
    # MITRE's own detection guidance, reduced to log sources and the Sysmon
    # event IDs that carry them -- this is what the coverage gap check compares
    # against what the lab actually collects.
    log_sources: list[str] = Field(default_factory=list)
    sysmon_event_codes: list[str] = Field(default_factory=list)
    url: str
    subtechniques: list[str] = Field(default_factory=list)
    kill_chain_phase: str | None = None


class AttackStatus(BaseModel):
    attack_version: str
    technique_count: int
    tactic_count: int
    sigma_available: bool
    sigma_rule_count: int
    sigma_sources: list[str] = Field(default_factory=list)
    finding_sink: str
