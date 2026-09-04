from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from necropsy.enums import KillChainPhase, Severity


class FunctionSummary(BaseModel):
    id: str
    name: str
    address: str
    size: int
    is_thunk: bool
    parameter_count: int
    calls: list[str] = Field(default_factory=list)
    has_decompilation: bool
    has_ai_summary: bool


class FunctionDetail(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    sample_id: str
    job_id: str | None
    name: str
    address: str
    size: int
    is_thunk: bool
    calling_convention: str | None
    parameter_count: int
    calls: list[str] = Field(default_factory=list)
    decompiled: str | None
    decompile_error: str | None
    code_sha256: str | None
    ai_summary: str | None
    ai_summarised_at: datetime | None
    created_at: datetime


class ToolingStatus(BaseModel):
    lief: bool
    yara: bool
    tlsh: bool
    libmagic: bool
    rizin: bool
    rizin_path: str | None
    ghidra: bool
    yara_rule_sources: list[dict[str, Any]] = Field(default_factory=list)


class CapabilityDescriptor(BaseModel):
    id: str
    title: str
    description: str
    severity: Severity
    kill_chain_phase: KillChainPhase
    attack_technique_ids: list[str]
    indicator_count: int
    min_hits: int
