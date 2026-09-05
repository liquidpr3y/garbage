"""Draft a YARA rule for a case, and only keep it if it survives validation."""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from necropsy.ai.client import AIClient
from necropsy.ai.report import build_context
from necropsy.ai.yara_draft import draft
from necropsy.analysis import artifacts as artifact_store
from necropsy.contracts.host import HostServices
from necropsy.db.models import AnalysisJob
from necropsy.db.repos import cases as cases_repo, samples as samples_repo
from necropsy.enums import ArtifactKind, Producer, Severity
from necropsy.intake.service import open_vault
from necropsy.jobs.tasks.base import emit_finding


class NoSampleToDetect(RuntimeError):
    pass


def run(session: Session, host: HostServices, job: AnalysisJob) -> dict[str, Any]:
    case = cases_repo.get(session, job.case_id)
    sample = samples_repo.get(session, job.sample_id) if job.sample_id else None
    if case is None or sample is None:
        raise NoSampleToDetect(f"job {job.id} needs a case and a sample")

    client = AIClient.from_settings()
    client.require_disclosure(case)

    actor = host.actor()
    context = build_context(session, case)
    vault = open_vault(session, actor=actor, case_id=case.id)

    with vault.open_plaintext(sample.sha256, actor=actor, reason="yara_draft") as path:
        result = draft(client, sample_path=path, context=context, sample_sha256=sample.sha256)

    if result.accepted and result.draft is not None:
        artifact_store.store_bytes(
            session,
            data=result.draft.rule_text.encode(),
            kind=ArtifactKind.YARA_RULE,
            sample_id=sample.id, job_id=job.id, case_id=case.id, actor=actor,
            meta={
                "rule_name": result.draft.rule_name,
                "validated": True,
                "attempts": result.attempts,
                "corpus_size": result.validation.corpus_size,
                "real_goodware": result.validation.real_goodware,
                "model": client.model,
            },
        )
        emit_finding(
            session, host, job,
            producer=Producer.AI,
            type="ai_yara_rule",
            title=f"Drafted and validated YARA rule: {result.draft.rule_name}",
            dedupe_key=f"ai_yara_rule:{result.draft.rule_name}",
            description=(
                f"{result.draft.rationale}\n\nValidated: compiles, matches this sample, "
                f"and did not match {result.validation.corpus_size} benign control(s)"
                + (
                    " including operator-supplied known-good binaries."
                    if result.validation.real_goodware
                    else ". Only synthetic controls were available -- set "
                    "NECROPSY_AI_GOODWARE_DIR for a real false-positive check."
                )
                + f"\n\nStated false-positive risk: {result.draft.false_positive_risk}"
            ),
            severity=Severity.INFO,
            confidence=result.draft.confidence,
            attack_technique_ids=result.draft.attack_technique_ids,
            evidence={**result.to_dict(), "rule_text": result.draft.rule_text},
        )
    else:
        # A rule that failed validation is not stored. Recording the failure is
        # more useful than a rule nobody should deploy.
        emit_finding(
            session, host, job,
            producer=Producer.AI,
            type="ai_yara_rejected",
            title="Drafted YARA rule failed validation and was discarded",
            dedupe_key="ai_yara_rejected",
            description=(
                f"After {result.attempts} attempt(s) the drafted rule still failed: "
                f"{result.validation.failure_text()} The rule was not stored -- a rule "
                "that does not match the sample, or that matches benign software, is "
                "worse than no rule because it will be trusted."
            ),
            severity=Severity.INFO, confidence=1.0,
            evidence=result.to_dict(),
        )

    return {**result.to_dict(), "usage": client.usage.to_dict()}
