from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from necropsy.enums import CaseStatus, Severity


class CaseCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    severity: Severity = Severity.INFO
    tags: list[str] = Field(default_factory=list)
    host_engagement_ref: str | None = None
    # Defaults false: sending decompiled code to a third-party API is a
    # contractual problem for client-engagement samples. Opt in per case.
    ai_disclosure_allowed: bool = False


class CaseUpdate(BaseModel):
    name: str | None = None
    status: CaseStatus | None = None
    severity: Severity | None = None
    summary: str | None = None
    tags: list[str] | None = None
    host_engagement_ref: str | None = None
    ai_disclosure_allowed: bool | None = None


class CaseOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    status: CaseStatus
    severity: Severity
    summary: str | None
    tags: list[str]
    host_engagement_ref: str | None
    ai_disclosure_allowed: bool
    created_at: datetime
    updated_at: datetime


class CaseDetail(CaseOut):
    counts: dict[str, int] = Field(default_factory=dict)
