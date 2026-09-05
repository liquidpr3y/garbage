"""Generate a case report via the Claude API."""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from necropsy.ai.client import AIClient
from necropsy.ai.report import generate
from necropsy.analysis import artifacts as artifact_store
from necropsy.contracts.host import HostServices
from necropsy.db.models import AnalysisJob
from necropsy.db.repos import cases as cases_repo, samples as samples_repo
from necropsy.enums import ArtifactKind, Producer, Severity
from necropsy.jobs.tasks.base import emit_finding


def run(session: Session, host: HostServices, job: AnalysisJob) -> dict[str, Any]:
    case = cases_repo.get(session, job.case_id)
    if case is None:
        raise RuntimeError(f"job {job.id} has no case")

    client = AIClient.from_settings()
    client.require_disclosure(case)

    outcome = generate(client, session, case)
    report = outcome.report

    # The case summary field has existed since Phase 1 for exactly this.
    case.summary = report.executive_summary
    session.flush()

    sample = None
    links = samples_repo.for_case(session, case.id)
    if links:
        sample = links[0].sample
        artifact_store.store_json(
            session,
            payload=report.model_dump(),
            kind=ArtifactKind.REPORT,
            sample_id=sample.id, job_id=job.id, case_id=case.id, actor=host.actor(),
            meta={"kind": "ai_case_report", "model": client.model},
        )

    if outcome.disagreement:
        emit_finding(
            session, host, job,
            producer=Producer.AI,
            type="ai_severity_disagreement",
            title="AI assessment disagrees with the derived findings",
            dedupe_key="ai_severity_disagreement",
            description=outcome.disagreement,
            severity=Severity.MEDIUM,
            confidence=1.0,
            evidence={
                "model_severity": report.suggested_severity,
                "model_confidence": report.confidence,
            },
        )

    if report.prompt_injection_observed.observed:
        emit_finding(
            session, host, job,
            producer=Producer.AI,
            type="prompt_injection_in_sample",
            title="Sample content contains text targeting an AI analyst",
            dedupe_key="prompt_injection_in_sample",
            description=(
                "Observed while generating the case report. The instruction was not "
                "followed. Noting the tradecraft: the author anticipated LLM triage."
            ),
            severity=Severity.MEDIUM, confidence=0.8,
            attack_technique_ids=["T1027"],
            evidence={"quote": report.prompt_injection_observed.quote[:300]},
        )

    return {**outcome.to_dict(), "usage": client.usage.to_dict()}
