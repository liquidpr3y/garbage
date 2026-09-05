"""The detonate job, driven against a fake target.

No VMware here; `test_sandbox_vmware.py` covers the vmrun layer. This exercises
the orchestration: lock, prepare, push, execute, collect, revert, telemetry,
findings, proposals -- and specifically that revert happens on every path.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import select

from necropsy.cases import service as case_service
from necropsy.db.models import Detonation
from necropsy.db.repos import actions as actions_repo, findings as findings_repo
from necropsy.db.repos import jobs as jobs_repo
from necropsy.enums import Arch, ArtifactKind, JobKind, JobState
from necropsy.intake import service as intake
from necropsy.jobs.tasks import detonate as detonate_mod
from necropsy.jobs.tasks.base import execute_job
from necropsy.sandbox.targets.base import (
    CollectedFile,
    DetonationTarget,
    ExecResult,
    TargetCapabilities,
    TargetError,
    TargetFingerprint,
)

# A failed run must still leave a record: see test_revert_runs_even_when_execution_fails.

BUSY_EVENTS = [
    {"event": {"code": "1"}, "process": {"name": "sample.exe", "parent": {"name": "explorer.exe"}}},
    {"event": {"code": "13"}, "registry": {"path": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\x"}},
    {"event": {"code": "3"}, "destination": {"ip": "185.220.101.44", "port": 443}},
    {"event": {"code": "22"}, "dns": {"question": {"name": "gate.evil-c2.ru"}}},
    {"event": {"code": "8"}},
    {"event": {"code": "1"}, "process": {"name": "vssadmin.exe", "parent": {"name": "sample.exe"},
                                          "command_line": "vssadmin delete shadows /all"}},
    {"event": {"code": "11"}, "file": {"path": r"C:\Users\a\AppData\Roaming\svc.exe"}},
    {"event": {"code": "1"}, "process": {"name": "cmd.exe", "parent": {"name": "sample.exe"}}},
    {"event": {"code": "17"}, "file": {"name": r"\\.\pipe\evil"}},
]


class FakeTarget(DetonationTarget):
    def __init__(self, *, arch: Arch = Arch.ARM64, fail_on: str | None = None) -> None:
        self.calls: list[str] = []
        self.fail_on = fail_on
        self.caps = TargetCapabilities(
            name="fake", arch=arch, os="windows", has_sysmon=True,
            supports_egress=True, snapshot="clean", guest_workdir="C:\\Users\\Public",
        )

    @classmethod
    def from_settings(cls, settings: Any, *, egress: bool = False) -> FakeTarget:
        return cls()

    def _step(self, name: str) -> None:
        self.calls.append(name)
        if self.fail_on == name:
            raise TargetError(f"fake failure in {name}")

    def prepare(self) -> None:
        self._step("prepare")

    def push(self, local: Path, guest_name: str) -> Any:
        self._step("push")
        return f"C:\\Users\\Public\\{guest_name}"

    def execute(self, guest_path: str, args: list[str], timeout_s: float) -> ExecResult:
        self._step("execute")
        now = datetime.now(timezone.utc)
        return ExecResult(started_at=now, finished_at=now, detail="fake run")

    def collect(self) -> list[CollectedFile]:
        self._step("collect")
        return [CollectedFile(name="screen.png", data=b"\x89PNG fake", kind="screenshot")]

    def revert(self) -> None:
        self.calls.append("revert")

    def fingerprint(self, *, sample_arch: Arch, native_code: bool) -> TargetFingerprint:
        return TargetFingerprint(
            target=self.caps.name, arch=self.caps.arch.value, os=self.caps.os,
            snapshot=self.caps.snapshot, egress=False,
            fidelity=self.caps.fidelity_for(sample_arch, native_code).value,
        )

    @property
    def guest_hostname(self) -> str | None:
        return "WIN-LAB-01"


@pytest.fixture
def target(monkeypatch: pytest.MonkeyPatch) -> FakeTarget:
    fake = FakeTarget()
    monkeypatch.setattr(detonate_mod, "build_target", lambda **_kw: fake)
    return fake


@pytest.fixture
def telemetry(monkeypatch: pytest.MonkeyPatch):  # type: ignore[no-untyped-def]
    def _set(events: list[dict], note: str = "fake telemetry") -> None:
        monkeypatch.setattr(
            detonate_mod, "_fetch_telemetry", lambda *a, **k: (events, note)
        )
    _set(BUSY_EVENTS)
    return _set


def _detonate(session, host, src: Path, *, egress=False, allow_ai=False):  # type: ignore[no-untyped-def]
    case = case_service.create_case(session, host, name="Detonation", ai_disclosure_allowed=allow_ai)
    session.commit()
    ingested = intake.ingest_file(session, host, case_id=case.id, src=src)
    session.commit()
    execute_job(ingested.job_id)

    job, _ = jobs_repo.enqueue_or_get(
        session, case_id=case.id, kind=JobKind.DETONATE, sample_id=ingested.sample.id,
        sample_sha256=ingested.sample.sha256, params={"egress": egress},
    )
    session.commit()
    execute_job(job.id)
    session.expire_all()
    return case, ingested.sample, jobs_repo.get(session, job.id)


def test_full_run_succeeds_and_records_the_detonation(
    session, host, target, telemetry, loader_sample: Path
) -> None:
    case, sample, job = _detonate(session, host, loader_sample)
    assert job.state is JobState.SUCCEEDED, job.error

    row = session.scalar(select(Detonation).where(Detonation.case_id == case.id))
    assert row.state == "completed"
    assert row.reverted is True
    assert row.telemetry_events == len(BUSY_EVENTS)
    assert row.readable is True
    assert row.guest_hostname == "WIN-LAB-01"


def test_lifecycle_order_and_revert_last(
    session, host, target, telemetry, loader_sample: Path
) -> None:
    _detonate(session, host, target and loader_sample)
    assert target.calls == ["prepare", "push", "execute", "collect", "revert"]


def test_revert_runs_even_when_execution_fails(
    session, host, monkeypatch, telemetry, loader_sample: Path
) -> None:
    """The invariant: a failed run must not leave a dirty snapshot."""
    fake = FakeTarget(fail_on="execute")
    monkeypatch.setattr(detonate_mod, "build_target", lambda **_kw: fake)

    case, _sample, job = _detonate(session, host, loader_sample)
    assert job.state is JobState.FAILED
    assert "fake failure in execute" in job.error
    assert fake.calls[-1] == "revert"

    row = session.scalar(select(Detonation).where(Detonation.case_id == case.id))
    assert row.state == "failed" and row.reverted is True


def test_revert_runs_even_when_prepare_fails(
    session, host, monkeypatch, telemetry, loader_sample: Path
) -> None:
    fake = FakeTarget(fail_on="prepare")
    monkeypatch.setattr(detonate_mod, "build_target", lambda **_kw: fake)

    _case, _sample, job = _detonate(session, host, loader_sample)
    assert job.state is JobState.FAILED
    assert fake.calls == ["prepare", "revert"]


def test_behavioural_findings_are_emitted_with_attack_ids(
    session, host, target, telemetry, loader_sample: Path
) -> None:
    case, _sample, _job = _detonate(session, host, loader_sample)
    findings = {f.type: f for f in findings_repo.for_case(session, case.id)}

    assert "behaviour:autorun_persistence" in findings
    assert "behaviour:remote_thread_injection" in findings
    assert "behaviour:recovery_destruction" in findings

    autorun = findings["behaviour:autorun_persistence"]
    assert autorun.attack_technique_ids == ["T1547.001"]
    assert autorun.kill_chain_phase.value == "installation"
    # loader_sample is x86_64 and the lab is ARM64, so the finding carries the
    # caveat with it -- a reader six months later sees how it was obtained.
    assert autorun.evidence["fidelity"] == "emulated"


def test_a_quiet_emulated_run_is_flagged_inconclusive(
    session, host, monkeypatch, telemetry, x86_packed_sample: Path
) -> None:
    """An x86 sample on the ARM lab that goes quiet must not read as clean."""
    telemetry([], "no events")
    fake = FakeTarget(arch=Arch.ARM64)
    monkeypatch.setattr(detonate_mod, "build_target", lambda **_kw: fake)

    case, _sample, job = _detonate(session, host, x86_packed_sample)
    assert job.state is JobState.SUCCEEDED
    assert job.result_summary["readable"] is False
    assert job.result_summary["fidelity"] == "emulated"

    findings = {f.type: f for f in findings_repo.for_case(session, case.id)}
    verdict = findings["detonation_inconclusive"]
    assert "INCONCLUSIVE" in verdict.description
    assert "emulation" in verdict.description


def test_artifacts_are_vaulted(
    session, host, target, telemetry, loader_sample: Path
) -> None:
    from necropsy.analysis import artifacts as artifact_store

    _case, sample, _job = _detonate(session, host, loader_sample)
    screenshot = artifact_store.latest(session, sample.id, ArtifactKind.SCREENSHOT)
    events = artifact_store.latest(session, sample.id, ArtifactKind.TELEMETRY)

    assert screenshot and events
    vault = intake.open_vault(session, actor="t")
    assert vault.path_for(screenshot.sha256).stat().st_mode & 0o777 == 0o400


def test_an_unreadable_run_proposes_a_decompile_not_another_quiet_run(
    session, host, monkeypatch, telemetry, x86_packed_sample: Path
) -> None:
    telemetry([], "no events")
    monkeypatch.setattr(detonate_mod, "build_target", lambda **_kw: FakeTarget())

    case, _sample, _job = _detonate(session, host, x86_packed_sample)
    kinds = [a.kind for a in actions_repo.for_case(session, case.id)]
    assert "ghidra_decompile" in kinds


def test_the_lab_lock_blocks_a_concurrent_run(
    session, host, target, telemetry, loader_sample: Path
) -> None:
    """One set of snapshots means one sample at a time."""
    from necropsy.sandbox.lock import SandboxBusy, detonation_lock

    with detonation_lock():
        with pytest.raises(SandboxBusy):
            with detonation_lock():
                pass


def test_telemetry_note_is_recorded_even_with_no_events(
    session, host, target, telemetry, loader_sample: Path
) -> None:
    """'We could not see' and 'nothing happened' must stay distinguishable."""
    telemetry([], "NO TELEMETRY FOR THIS HOST, but 40 events from other hosts")
    case, _sample, job = _detonate(session, host, loader_sample)

    row = session.scalar(select(Detonation).where(Detonation.case_id == case.id))
    assert "other hosts" in row.telemetry_note
    assert row.readable is False
    assert job.result_summary["telemetry_note"] == row.telemetry_note
