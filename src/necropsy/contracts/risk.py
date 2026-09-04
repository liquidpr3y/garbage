"""Risk vocabulary.

The pentest module's "credentialed scan against production" and Necropsy's
"egress-permitted detonation" must be the same shape and land in the same
colour band, because one GUI component renders both. That shared component is
the whole reason this module exists.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field


class RiskBand(str, Enum):
    MINIMAL = "minimal"
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    SEVERE = "severe"


class RiskFactor(BaseModel):
    """One reason an action is more (or less) dangerous than the baseline.

    ``weight`` is always stated as a positive magnitude; ``direction`` says
    whether it raises or lowers risk. Keeping those separate means the GUI can
    render mitigating factors ("no egress", "snapshot verified") in the same
    list as aggravating ones without sign confusion.
    """

    code: str
    label: str
    weight: float = Field(ge=0, le=10)
    direction: Literal[1, -1] = 1

    @property
    def signed_weight(self) -> float:
        return self.weight * self.direction


class RiskScore(BaseModel):
    """A 0-10 score plus the factors that produced it.

    The factors are not decoration. The operator is being asked to accept blast
    radius, so the GUI shows *why*, not just a number.
    """

    value: float = Field(ge=0, le=10)
    band: RiskBand
    factors: list[RiskFactor] = Field(default_factory=list)


class ActionProposal(BaseModel):
    """A next step offered to the operator after a stage completes.

    Necropsy never escalates on its own: proposals are inert until a human
    accepts one. ``available`` is false for kinds a later phase will implement,
    so the GUI can show the full decision space and grey out what is not built
    yet rather than silently hiding it.
    """

    kind: str
    title: str
    rationale: str
    risk: RiskScore
    estimated_cost_s: int | None = None
    params: dict[str, Any] = Field(default_factory=dict)
    available: bool = True
    unavailable_reason: str | None = None


def band_for(value: float) -> RiskBand:
    if value < 2:
        return RiskBand.MINIMAL
    if value < 4:
        return RiskBand.LOW
    if value < 6.5:
        return RiskBand.MODERATE
    if value < 8.5:
        return RiskBand.HIGH
    return RiskBand.SEVERE


def score_factors(base: float, factors: list[RiskFactor]) -> RiskScore:
    """Sum signed factor weights onto a baseline and clamp to 0-10."""
    value = base + sum(f.signed_weight for f in factors)
    value = max(0.0, min(10.0, round(value, 1)))
    return RiskScore(value=value, band=band_for(value), factors=factors)
