"""Standalone YARA re-scan.

Separate from static triage because rule sets change far more often than
samples do. After writing a rule you want to sweep existing cases cheaply,
without re-parsing every PE.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from necropsy.analysis import yara_rules
from necropsy.contracts.host import HostServices
from necropsy.db.models import AnalysisJob
from necropsy.db.repos import samples as samples_repo
from necropsy.intake.service import open_vault
from necropsy.jobs.tasks.static_triage import _emit_yara_findings


def run(session: Session, host: HostServices, job: AnalysisJob) -> dict[str, Any]:
    sample = samples_repo.get(session, job.sample_id) if job.sample_id else None
    if sample is None:
        raise RuntimeError(f"job {job.id} has no sample to scan")

    if not yara_rules.have_yara():
        return {"available": False, "reason": "yara-python not installed", "hits": []}

    actor = host.actor()
    vault = open_vault(session, actor=actor, case_id=job.case_id)
    with vault.open_plaintext(sample.sha256, actor=actor, reason="yara_scan") as path:
        result = yara_rules.scan(path)

    _emit_yara_findings(session, host, job, result)
    return result.summary()
