"""Summarise decompiled functions via the Claude API."""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from necropsy.ai.client import AIClient
from necropsy.ai.summarise import summarise_sample
from necropsy.contracts.host import HostServices
from necropsy.db.models import AnalysisJob
from necropsy.db.repos import cases as cases_repo, samples as samples_repo
from necropsy.enums import Producer, Severity
from necropsy.jobs.tasks.base import emit_finding


class NothingToSummarise(RuntimeError):
    pass


def run(session: Session, host: HostServices, job: AnalysisJob) -> dict[str, Any]:
    sample = samples_repo.get(session, job.sample_id) if job.sample_id else None
    if sample is None:
        raise NothingToSummarise(f"job {job.id} has no sample")

    case = cases_repo.get(session, job.case_id)
    client = AIClient.from_settings()
    client.require_disclosure(case)

    outcome = summarise_sample(client, session, sample.id)
    if outcome.candidates == 0:
        raise NothingToSummarise(
            "no un-summarised decompiled functions on this sample; run a Ghidra "
            "decompile pass first"
        )

    _report_injection(session, host, job, outcome.injection_attempts)

    if outcome.techniques:
        emit_finding(
            session, host, job,
            producer=Producer.AI,
            type="ai_function_techniques",
            title=f"AI identified {len(outcome.techniques)} technique(s) in decompiled code",
            dedupe_key="ai_function_techniques",
            description=(
                "Techniques the model attributed to individual functions. Model-derived "
                "and unverified: treat as leads for a human to confirm against the "
                "decompilation, not as findings in their own right."
            ),
            severity=Severity.INFO,
            confidence=0.4,
            attack_technique_ids=outcome.techniques,
            evidence=outcome.to_dict(),
        )

    return {**outcome.to_dict(), **{"usage": client.usage.to_dict()}}


def _report_injection(
    session: Session, host: HostServices, job: AnalysisJob, attempts: list[str]
) -> None:
    """An injection attempt in a sample is itself intelligence.

    A sample carrying text aimed at an analysing model tells you the author
    expects LLM-assisted triage. That is worth a finding in its own right.
    """
    if not attempts:
        return
    emit_finding(
        session, host, job,
        producer=Producer.AI,
        type="prompt_injection_in_sample",
        title="Sample contains text targeting an AI analyst",
        dedupe_key="prompt_injection_in_sample",
        description=(
            "Content in this sample was written to manipulate a model reading it. "
            "The instruction was not followed -- sample content is handled as data, "
            "never as instruction. Worth noting as tradecraft: the author anticipated "
            "automated LLM triage."
        ),
        severity=Severity.MEDIUM,
        confidence=0.8,
        attack_technique_ids=["T1027"],
        evidence={"quotes": attempts[:5]},
    )
