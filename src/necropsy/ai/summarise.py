"""Per-function summaries of a decompilation.

Batched, capped, and ordered by how much a human would care: the largest
non-thunk functions first. A 4,000-function binary must not turn into 4,000
API calls, and the tail of tiny wrappers is where the least value is.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from necropsy.ai.client import AIClient
from necropsy.ai.prompts import FUNCTION_SUMMARY_TASK, envelope, new_nonce, system_prompt
from necropsy.ai.schemas import FunctionSummaryBatch
from necropsy.config import get_settings
from necropsy.db.base import utcnow
from necropsy.db.models import DecompiledFunction

log = logging.getLogger(__name__)


@dataclass
class SummaryOutcome:
    summarised: int = 0
    batches: int = 0
    skipped_thunks: int = 0
    candidates: int = 0
    techniques: list[str] = field(default_factory=list)
    injection_attempts: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "summarised": self.summarised,
            "batches": self.batches,
            "skipped_thunks": self.skipped_thunks,
            "candidates": self.candidates,
            "techniques": self.techniques,
            "injection_attempts": self.injection_attempts,
        }


def candidates(session: Session, sample_id: str, limit: int) -> list[DecompiledFunction]:
    """The functions worth spending tokens on: decompiled, real, largest first."""
    stmt = (
        select(DecompiledFunction)
        .where(
            DecompiledFunction.sample_id == sample_id,
            DecompiledFunction.decompiled.is_not(None),
            DecompiledFunction.is_thunk.is_(False),
            DecompiledFunction.ai_summary.is_(None),
        )
        .order_by(DecompiledFunction.size.desc())
        .limit(limit)
    )
    return list(session.scalars(stmt))


def summarise_sample(client: AIClient, session: Session, sample_id: str) -> SummaryOutcome:
    settings = get_settings()
    outcome = SummaryOutcome()

    functions = candidates(session, sample_id, settings.ai_max_functions)
    outcome.candidates = len(functions)
    if not functions:
        return outcome

    batch_size = max(1, settings.ai_function_batch_size)
    techniques: set[str] = set()

    for start in range(0, len(functions), batch_size):
        batch = functions[start : start + batch_size]
        result = _summarise_batch(client, batch)
        outcome.batches += 1

        if result.prompt_injection_observed.observed:
            outcome.injection_attempts.append(result.prompt_injection_observed.quote[:300])

        by_address = {f.address: f for f in batch}
        for summary in result.summaries:
            function = by_address.get(summary.address)
            if function is None:
                # The model invented or mangled an address. Drop it rather than
                # guessing which function it meant.
                log.warning("AI returned an unknown function address %r", summary.address)
                continue
            function.ai_summary = _render(summary)
            function.ai_summarised_at = utcnow()
            techniques.update(summary.attack_technique_ids)
            outcome.summarised += 1
        session.flush()

    outcome.techniques = sorted(techniques)
    return outcome


def _summarise_batch(client: AIClient, batch: list[DecompiledFunction]) -> FunctionSummaryBatch:
    settings = get_settings()
    nonce = new_nonce()
    blocks = []
    for function in batch:
        body = (function.decompiled or "")[: settings.ai_max_decompiled_chars]
        blocks.append(
            f"### address={function.address} name={function.name} "
            f"size={function.size} calls={', '.join(function.calls[:12])}\n{body}"
        )

    return client.parse(
        system=system_prompt(FUNCTION_SUMMARY_TASK, nonce),
        user=envelope("\n\n".join(blocks), nonce, label="decompiled-functions"),
        schema=FunctionSummaryBatch,
    )


def _render(summary: Any) -> str:
    """Store the summary as readable text, labelled as model-generated."""
    lines = [summary.purpose.strip()]
    if summary.behaviours:
        lines.append("Behaviours: " + "; ".join(summary.behaviours))
    if summary.attack_technique_ids:
        lines.append("ATT&CK: " + ", ".join(summary.attack_technique_ids))
    lines.append(
        f"[AI-generated, confidence {summary.confidence:.2f}"
        + (", flagged suspicious" if summary.suspicious else "")
        + "]"
    )
    return "\n".join(lines)
