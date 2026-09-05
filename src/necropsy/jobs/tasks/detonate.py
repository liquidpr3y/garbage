"""Detonation: run a sample somewhere that is not this machine, and watch.

Ordering and invariants, in the order they matter:

* Nothing reaches here without a human accepting a risk-scored proposal. The
  job is the consequence of a decision, not a decision.
* `revert()` runs in a `finally`. A failed run must not leave a dirty snapshot
  for the next sample to inherit -- that contaminates evidence silently.
* The lab lock is held for the whole run. One set of snapshots, one sample.
* A quiet run is never reported as a clean one. `behaviour.analyse` decides
  whether the run is readable at all, and on an emulated pairing silence is
  the expected result of failing to start.
"""

from __future__ import annotations

import logging
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from necropsy.analysis import artifacts as artifact_store
from necropsy.config import get_settings
from necropsy.contracts.host import HostServices
from necropsy.db.models import AnalysisJob, Detonation
from necropsy.db.repos import cases as cases_repo, samples as samples_repo
from necropsy.elastic.client import ElasticClient, ElasticError
from necropsy.elastic.sysmon import TelemetryWindow, coverage_probe, window_query
from necropsy.enums import ArtifactKind, FileType, KillChainPhase, Producer, Severity
from necropsy.intake.service import open_vault
from necropsy.sandbox import behaviour as behaviour_mod
from necropsy.sandbox.collectors.pcap import PcapCapture, summarise
from necropsy.sandbox.lock import detonation_lock
from necropsy.sandbox.targets import build_target
from necropsy.sandbox.targets.base import EmulationFidelity
from necropsy.jobs.tasks.base import emit_finding
from necropsy.jobs.tasks.propose import publish_proposals
from necropsy.scoring.proposals import after_detonation

log = logging.getLogger(__name__)

NATIVE_TYPES = {FileType.PE, FileType.ELF, FileType.MACHO}

GUEST_EXTENSIONS = {
    FileType.PE: ".exe",
    FileType.OFFICE: ".doc",
    FileType.SCRIPT: ".js",
    FileType.SHORTCUT: ".lnk",
    FileType.PDF: ".pdf",
}


def run(session: Session, host: HostServices, job: AnalysisJob) -> dict[str, Any]:
    settings = get_settings()
    sample = samples_repo.get(session, job.sample_id) if job.sample_id else None
    if sample is None:
        raise RuntimeError(f"job {job.id} has no sample to detonate")

    egress = bool((job.params or {}).get("egress", False))
    actor = host.actor()
    native_code = sample.file_type in NATIVE_TYPES

    target = build_target(egress=egress)
    fingerprint = target.fingerprint(sample_arch=sample.arch, native_code=native_code)
    fidelity = EmulationFidelity(fingerprint.fidelity)

    detonation = Detonation(
        case_id=job.case_id, sample_id=sample.id, job_id=job.id,
        target=fingerprint.target, target_arch=fingerprint.arch, target_os=fingerprint.os,
        snapshot=fingerprint.snapshot, egress=egress, fidelity=fingerprint.fidelity,
        fingerprint=fingerprint.to_dict(), guest_hostname=target.guest_hostname,
        telemetry_source=settings.elastic_sysmon_index if settings.elastic_url else None,
    )
    session.add(detonation)
    # Committed before the run, not after. If the detonation fails, the job's
    # transaction is rolled back -- and a run that pushed a live sample into a
    # guest must leave a record that it happened and that the lab was reverted,
    # regardless of how it ended. Chain of custody cannot be contingent on
    # success.
    session.commit()

    started = datetime.now(timezone.utc)
    pcap_path = Path(tempfile.mkstemp(prefix="necropsy-", suffix=".pcap")[1])
    collected: list[Any] = []
    exec_detail = ""
    pcap_error: str | None = None

    try:
        with detonation_lock():
            vault = open_vault(session, actor=actor, case_id=job.case_id)
            with vault.open_plaintext(sample.sha256, actor=actor, reason="detonate") as local:
                guest_name = _guest_name(sample)
                try:
                    target.prepare()
                    with _make_capture(settings, pcap_path) as capture:
                        guest_path = target.push(local, guest_name)
                        detonation.guest_path = str(guest_path)
                        result = target.execute(
                            str(guest_path), [], settings.sandbox_run_seconds
                        )
                        exec_detail = result.detail
                        pcap_error = getattr(capture, "error", None)
                    collected = target.collect()
                finally:
                    # Invariant: the lab is always returned to a clean snapshot.
                    target.revert()
                    detonation.reverted = True
    except Exception as exc:
        detonation.state = "failed"
        detonation.error = f"{type(exc).__name__}: {exc}"
        detonation.finished_at = datetime.now(timezone.utc)
        detonation.reverted = detonation.reverted or False
        # Commit the failure before re-raising, or the rollback erases it.
        session.commit()
        raise
    finally:
        finished = datetime.now(timezone.utc)
        if detonation.finished_at is None:
            detonation.finished_at = finished
        detonation.run_seconds = int((finished - started).total_seconds())

    detonation.exec_detail = exec_detail

    network = summarise(pcap_path) if pcap_path.exists() and pcap_path.stat().st_size else None
    if pcap_error and network is None:
        detonation.network_summary = {"error": pcap_error}
    elif network is not None:
        detonation.network_summary = network.to_dict()

    _store_run_artifacts(
        session, job, sample, actor=actor, pcap_path=pcap_path, collected=collected
    )
    pcap_path.unlink(missing_ok=True)

    events, telemetry_note = _fetch_telemetry(settings, started, finished, target.guest_hostname)
    detonation.telemetry_events = len(events)
    detonation.telemetry_note = telemetry_note

    report = behaviour_mod.analyse(
        events, fidelity=fidelity, sample_image=detonation.guest_path
    )
    detonation.behaviour_summary = report.summary()
    detonation.readable = report.readable
    detonation.verdict_note = report.verdict_note
    detonation.state = "completed"
    session.flush()

    if events:
        artifact_store.store_json(
            session, payload={"events": events[:5000]}, kind=ArtifactKind.TELEMETRY,
            sample_id=sample.id, job_id=job.id, case_id=job.case_id, actor=actor,
            meta={"count": len(events), "detonation_id": detonation.id},
        )

    _emit_findings(session, host, job, detonation, report, network)

    case = cases_repo.get(session, job.case_id)
    proposals = after_detonation(
        sample,
        target_arches=settings.target_arches,
        readable=report.readable,
        behaviours=[b.id for b in report.behaviours],
        egress_used=egress,
        ai_disclosure_allowed=bool(case and case.ai_disclosure_allowed),
    )
    publish_proposals(session, host, job, sample, proposals)

    return {
        "detonation_id": detonation.id,
        "target": fingerprint.target,
        "fidelity": fingerprint.fidelity,
        "egress": egress,
        "run_seconds": detonation.run_seconds,
        "telemetry_events": len(events),
        "telemetry_note": telemetry_note,
        "readable": report.readable,
        "verdict": report.verdict_note,
        "behaviours": [b.id for b in report.behaviours],
        "attack_techniques": sorted({t for b in report.behaviours for t in b.attack}),
        "network": detonation.network_summary,
        "reverted": detonation.reverted,
    }


class _NullCapture:
    """Stands in when no capture interface is configured."""

    error = "no NECROPSY_SANDBOX_PCAP_INTERFACE configured; no packets were captured"

    def __enter__(self) -> _NullCapture:
        return self

    def __exit__(self, *_exc: object) -> None:
        return None


def _make_capture(settings: Any, pcap_path: Path) -> Any:
    if not settings.sandbox_pcap_interface:
        return _NullCapture()
    return PcapCapture(
        settings.sandbox_pcap_interface, pcap_path, tcpdump=settings.tcpdump_path
    )


def _guest_name(sample: Any) -> str:
    extension = GUEST_EXTENSIONS.get(sample.file_type, ".bin")
    return f"sample_{sample.sha256[:12]}{extension}"


def _store_run_artifacts(
    session: Session,
    job: AnalysisJob,
    sample: Any,
    *,
    actor: str,
    pcap_path: Path,
    collected: list[Any],
) -> None:
    if pcap_path.exists() and pcap_path.stat().st_size:
        artifact_store.store_bytes(
            session, data=pcap_path.read_bytes(), kind=ArtifactKind.PCAP,
            sample_id=sample.id, job_id=job.id, case_id=job.case_id, actor=actor,
            meta={"content_type": "application/vnd.tcpdump.pcap"},
        )
    for item in collected:
        kind = ArtifactKind.SCREENSHOT if item.kind == "screenshot" else ArtifactKind.OTHER
        artifact_store.store_bytes(
            session, data=item.data, kind=kind, sample_id=sample.id, job_id=job.id,
            case_id=job.case_id, actor=actor, meta={"name": item.name},
        )


def _fetch_telemetry(
    settings: Any, started: datetime, finished: datetime, hostname: str | None
) -> tuple[list[dict[str, Any]], str]:
    """Read the guest's Sysmon events back out of the lab's Elastic cluster.

    Returns (events, note). The note matters as much as the events: an empty
    result from an unreachable cluster and an empty result from a dormant
    sample mean opposite things, and only one of them is about the sample.
    """
    client = ElasticClient.try_from_settings()
    if client is None:
        return [], (
            "Elastic is not configured, so no host telemetry was collected. "
            "Behavioural findings for this run come from packet capture only."
        )

    # The Elastic Agent batches; querying the instant the VM stops finds nothing.
    time.sleep(max(0, settings.elastic_settle_seconds))

    window = TelemetryWindow(
        start=started - timedelta(seconds=30),
        end=finished + timedelta(seconds=settings.elastic_settle_seconds + 30),
        host=hostname,
    )
    try:
        result = client.search(settings.elastic_sysmon_index, window_query(window))
    except ElasticError as exc:
        return [], f"Elastic query failed ({exc}); no host telemetry for this run."

    if result.error:
        return [], f"Elastic query failed ({result.error}); no host telemetry for this run."
    if result.sources:
        return result.sources, f"{result.total} Sysmon event(s) from {hostname or 'the guest'}."

    # Empty. Distinguish "the guest was quiet" from "we are looking in the
    # wrong place" -- reporting the second as the first is how a live sample
    # gets written off as inert.
    probe = client.search(settings.elastic_sysmon_index, coverage_probe(window))
    if probe.total:
        seen = sorted({
            (s.get("host", {}) or {}).get("name", "?") for s in probe.sources
        })
        return [], (
            f"NO TELEMETRY FOR THIS HOST, but {probe.total} event(s) from other hosts "
            f"({', '.join(seen)}) are present in the same window. The host filter is "
            f"wrong, not the sample: check NECROPSY_SANDBOX_GUEST_HOSTNAME "
            f"(currently {hostname!r}). Treat this run as uncollected, not quiet."
        )
    return [], (
        "No events in the index for this window from any host. Either the Elastic "
        "Agent is not running in the guest, Sysmon is not installed, or the index "
        "pattern is wrong. Treat this run as uncollected, not quiet."
    )


def _emit_findings(
    session: Session,
    host: HostServices,
    job: AnalysisJob,
    detonation: Detonation,
    report: behaviour_mod.BehaviourReport,
    network: Any,
) -> None:
    for item in report.behaviours:
        emit_finding(
            session, host, job,
            producer=Producer.SANDBOX,
            type=f"behaviour:{item.id}",
            title=item.title,
            dedupe_key=f"behaviour:{item.id}",
            description=item.description,
            severity=item.severity,
            confidence=item.confidence,
            attack_technique_ids=item.attack,
            kill_chain_phase=item.kill_chain_phase,
            evidence={**item.evidence, "detonation_id": detonation.id,
                      "fidelity": detonation.fidelity},
        )

    if not report.readable:
        emit_finding(
            session, host, job,
            producer=Producer.SANDBOX,
            type="detonation_inconclusive",
            title="Detonation produced no readable result",
            dedupe_key=f"detonation_inconclusive:{detonation.id}",
            description=report.verdict_note,
            severity=Severity.INFO, confidence=1.0,
            evidence={
                "detonation_id": detonation.id,
                "events": detonation.telemetry_events,
                "fidelity": detonation.fidelity,
                "telemetry_note": detonation.telemetry_note,
            },
        )

    if network is not None and (network.dns_queries or network.tls_sni or network.contacted_ips):
        emit_finding(
            session, host, job,
            producer=Producer.ZEEK,
            type="sandbox_network_indicators",
            title=(
                f"{len(network.contacted_ips)} IP(s), {len(network.dns_queries)} DNS "
                f"quer(ies), {len(network.tls_sni)} TLS name(s) observed on the wire"
            ),
            dedupe_key=f"sandbox_network:{detonation.id}",
            description=(
                "Captured on the host side of the sandbox network, so the sample could "
                "neither see nor suppress it. TLS SNI and DNS names survive encryption "
                "and are the most hunt-ready indicators this run produced."
            ),
            severity=Severity.HIGH, confidence=0.9,
            attack_technique_ids=["T1071"],
            kill_chain_phase=KillChainPhase.COMMAND_AND_CONTROL,
            evidence=network.to_dict(),
        )
