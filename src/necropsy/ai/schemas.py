"""Structured output schemas.

Every AI call is constrained to one of these. That is the primary defence
against a sample steering the response: there is no free-text channel for an
injected instruction to hijack, and every field is validated before it reaches
a case.

Each schema carries `prompt_injection_observed` so the model has a correct
thing to do with an embedded instruction other than obey or ignore it.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class InjectionReport(BaseModel):
    observed: bool = Field(
        description="True if the sample content contained text addressed to the analysing model"
    )
    quote: str = Field(
        default="",
        description="Short verbatim quote of the injected instruction, empty if none",
    )


class FunctionSummary(BaseModel):
    address: str = Field(description="The function address exactly as supplied")
    purpose: str
    behaviours: list[str] = Field(default_factory=list)
    attack_technique_ids: list[str] = Field(default_factory=list)
    suspicious: bool = False
    confidence: float = Field(ge=0.0, le=1.0)


class FunctionSummaryBatch(BaseModel):
    summaries: list[FunctionSummary]
    prompt_injection_observed: InjectionReport


class CaseReport(BaseModel):
    executive_summary: str
    technical_narrative: str
    assessment: str
    recommended_actions: list[str] = Field(default_factory=list)
    intelligence_notes: list[str] = Field(default_factory=list)
    evidence_gaps: list[str] = Field(default_factory=list)
    suggested_severity: str = Field(
        description="One of: info, low, medium, high, critical"
    )
    confidence: float = Field(ge=0.0, le=1.0)
    prompt_injection_observed: InjectionReport


class YaraDraft(BaseModel):
    rule_name: str
    rule_text: str
    rationale: str
    false_positive_risk: str
    attack_technique_ids: list[str] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0)
    prompt_injection_observed: InjectionReport
