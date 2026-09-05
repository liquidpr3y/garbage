"""Case report generation.

The model is given the case's derived findings -- not raw sample bytes -- plus
the ATT&CK rollup and the detonation verdict. That framing is deliberate: the
report should synthesise what the pipeline established, and the pipeline's
honesty about what it could *not* establish is the part most worth carrying
into a human-readable document.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from necropsy.ai.client import AIClient
from necropsy.ai.prompts import CASE_REPORT_TASK, envelope, new_nonce, system_prompt
from necropsy.ai.schemas import CaseReport
from necropsy.attack import coverage as coverage_mod
from necropsy.db.models import Case, Detonation
from necropsy.db.repos import findings as findings_repo, samples as samples_repo
from necropsy.enums import Severity

MAX_FINDINGS = 200
SEVERITY_ORDER = {
    Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2,
    Severity.LOW: 3, Severity.INFO: 4,
}


@dataclass
class ReportOutcome:
    report: CaseReport
    disagreement: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "suggested_severity": self.report.suggested_severity,
            "confidence": self.report.confidence,
            "recommended_actions": len(self.report.recommended_actions),
            "evidence_gaps": len(self.report.evidence_gaps),
            "disagreement": self.disagreement,
            "injection_observed": self.report.prompt_injection_observed.observed,
        }


def build_context(session: Session, case: Case) -> str:
    """Everything the pipeline established, as compact JSON."""
    findings = sorted(
        findings_repo.for_case(session, case.id, limit=MAX_FINDINGS),
        key=lambda f: (SEVERITY_ORDER[f.severity], -f.confidence),
    )
    coverage = coverage_mod.build(session, case.id)
    detonations = list(
        session.scalars(
            select(Detonation)
            .where(Detonation.case_id == case.id)
            .order_by(Detonation.started_at.desc())
        )
    )
    case_samples = samples_repo.for_case(session, case.id)

    payload = {
        "case": {"name": case.name, "severity": case.severity.value, "tags": case.tags},
        "samples": [
            {
                "sha256": link.sample.sha256,
                "observed_filename": link.observed_filename,
                "file_type": link.sample.file_type.value,
                "arch": link.sample.arch.value,
                "size": link.sample.size,
                "entropy": link.sample.entropy,
                "imphash": (link.sample.identity or {}).get("imphash"),
            }
            for link in case_samples
        ],
        "findings": [
            {
                "type": f.type,
                "title": f.title,
                "severity": f.severity.value,
                "confidence": f.confidence,
                "producer": f.producer.value,
                "attack": f.attack_technique_ids,
                "description": (f.description or "")[:600],
            }
            for f in findings
        ],
        "attack_coverage": {
            "technique_count": coverage.technique_count,
            "observed": coverage.observed_count,
            "inferred": coverage.inferred_count,
            "tactics": [
                {"name": t.name, "techniques": [c.technique.id for c in t.cells]}
                for t in coverage.tactics
            ],
            "detection_gaps": [g.to_dict() for g in coverage.detection_gaps],
            "notes": coverage.notes,
        },
        "detonations": [
            {
                "target": d.target, "fidelity": d.fidelity, "egress": d.egress,
                "telemetry_events": d.telemetry_events,
                "readable": d.readable, "verdict": d.verdict_note,
                "behaviours": (d.behaviour_summary or {}).get("behaviours", []),
                "network": {
                    k: v for k, v in (d.network_summary or {}).items()
                    if k in ("dns_queries", "tls_sni", "contacted_ips")
                },
            }
            for d in detonations
        ],
    }
    return json.dumps(payload, indent=1, default=str)


def generate(client: AIClient, session: Session, case: Case) -> ReportOutcome:
    nonce = new_nonce()
    context = build_context(session, case)
    report = client.parse(
        system=system_prompt(CASE_REPORT_TASK, nonce),
        user=envelope(context, nonce, label="case-findings"),
        schema=CaseReport,
    )
    return ReportOutcome(report=report, disagreement=_disagreement(session, case, report))


def _disagreement(session: Session, case: Case, report: CaseReport) -> str | None:
    """Flag when the model's severity contradicts the derived findings.

    Not to override it -- to surface it. A model talked down by content inside
    the sample, and a model that has spotted something the rules did not, look
    the same from here; both are worth a human's attention.
    """
    findings = findings_repo.for_case(session, case.id, limit=MAX_FINDINGS)
    if not findings:
        return None

    worst = min(SEVERITY_ORDER[f.severity] for f in findings)
    try:
        suggested = SEVERITY_ORDER[Severity(report.suggested_severity.lower())]
    except ValueError:
        return f"the model suggested an unrecognised severity {report.suggested_severity!r}"

    if suggested > worst + 1:
        worst_name = next(
            f.severity.value for f in findings if SEVERITY_ORDER[f.severity] == worst
        )
        return (
            f"the model assessed this case as {report.suggested_severity}, but the "
            f"pipeline produced at least one {worst_name} finding derived without a "
            "model. Read the finding list before accepting the summary."
        )
    return None
