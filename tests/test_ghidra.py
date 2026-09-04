"""Ghidra headless driver.

The real-run test is opt-in: it needs a Ghidra installation and takes tens of
seconds, so CI skips it unless GHIDRA_HOME (or NECROPSY_GHIDRA_HOME) points at
one. Everything that does not need Ghidra installed is tested unconditionally,
including the path an analyst without it actually hits.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from necropsy.analysis import ghidra
from necropsy.cases import service as case_service
from necropsy.db.repos import findings as findings_repo, jobs as jobs_repo
from necropsy.enums import JobKind, JobState
from necropsy.intake import service as intake
from necropsy.jobs.tasks.base import execute_job

needs_ghidra = pytest.mark.skipif(
    not ghidra.have_ghidra(), reason="Ghidra not installed (set GHIDRA_HOME)"
)


def _prepare(session, host, src: Path):  # type: ignore[no-untyped-def]
    case = case_service.create_case(session, host, name="Decompile")
    session.commit()
    result = intake.ingest_file(session, host, case_id=case.id, src=src)
    session.commit()
    execute_job(result.job_id)
    session.expire_all()
    return case, result.sample


def test_missing_ghidra_is_reported_not_raised(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ghidra, "headless_binary", lambda: None)
    result = ghidra.decompile(tmp_path / "nothing.exe")
    assert result.available is False
    assert "NECROPSY_GHIDRA_HOME" in (result.error or "")
    assert result.functions == []


def test_decompile_job_fails_clearly_without_ghidra(
    session, host, loader_sample: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An analyst without Ghidra should get a sentence, not a stack trace."""
    monkeypatch.setattr(ghidra, "headless_binary", lambda: None)
    case, sample = _prepare(session, host, loader_sample)

    job, _ = jobs_repo.enqueue_or_get(
        session, case_id=case.id, kind=JobKind.GHIDRA_DECOMPILE,
        sample_id=sample.id, sample_sha256=sample.sha256,
    )
    session.commit()
    execute_job(job.id)
    session.expire_all()

    done = jobs_repo.get(session, job.id)
    assert done.state is JobState.FAILED
    assert "GhidraNotInstalled" in done.error
    assert "NECROPSY_GHIDRA_HOME" in done.error


def test_proposal_is_marked_unavailable_without_ghidra(monkeypatch: pytest.MonkeyPatch) -> None:
    import necropsy.scoring.proposals as proposals_mod

    monkeypatch.setattr(ghidra, "have_ghidra", lambda: False)
    reason = proposals_mod._tooling_note(JobKind.GHIDRA_DECOMPILE)
    assert reason and "NECROPSY_GHIDRA_HOME" in reason


def test_normalised_hash_ignores_whitespace_only_changes() -> None:
    from necropsy.jobs.tasks.ghidra_decompile import _normalised_hash

    a = _normalised_hash("int f(void)\n{\n  return 1;\n}")
    b = _normalised_hash("int f(void) {   return 1; }")
    assert a == b and a is not None
    assert _normalised_hash(None) is None


def test_capability_detection_over_a_decompilation() -> None:
    """The reason a decompile is worth 8 minutes on a runtime-resolving sample."""
    from necropsy.jobs.tasks.ghidra_decompile import _detect_in_decompilation

    functions = [
        {
            "name": "FUN_140001000",
            "calls": ["GetProcAddress", "LoadLibraryA"],
            "decompiled": (
                'pvVar1 = GetProcAddress(hMod, "VirtualAllocEx");\n'
                'pvVar2 = GetProcAddress(hMod, "WriteProcessMemory");\n'
                'pvVar3 = GetProcAddress(hMod, "CreateRemoteThread");\n'
            ),
        }
    ]
    found = {h.capability.id for h in _detect_in_decompilation(functions)}
    assert "process_injection" in found
    assert "dynamic_api_resolution" in found


@needs_ghidra
@pytest.mark.slow
def test_real_decompile_run(session, host, tmp_path: Path) -> None:
    from pebuilder import PESpec, build

    # Real x86-64: sub rsp,0x28 / mov eax,42 / add eax,1 / add rsp,0x28 / ret
    code = bytes(
        [0x48, 0x83, 0xEC, 0x28, 0xB8, 0x2A, 0x00, 0x00, 0x00,
         0x83, 0xC0, 0x01, 0x48, 0x83, 0xC4, 0x28, 0xC3]
    ) + b"\x90" * 64
    src = build(
        tmp_path / "real.exe",
        PESpec(imports={"kernel32.dll": ["VirtualAllocEx", "WriteProcessMemory"]},
               text_filler=code),
    )
    case, sample = _prepare(session, host, src)

    job, _ = jobs_repo.enqueue_or_get(
        session, case_id=case.id, kind=JobKind.GHIDRA_DECOMPILE,
        sample_id=sample.id, sample_sha256=sample.sha256,
    )
    session.commit()
    execute_job(job.id)
    session.expire_all()

    done = jobs_repo.get(session, job.id)
    assert done.state is JobState.SUCCEEDED, done.error
    assert done.result_summary["stored_functions"] >= 1
    assert done.result_summary["language"].startswith("x86:LE:64")

    from necropsy.db.models import DecompiledFunction
    from sqlalchemy import select

    rows = list(session.scalars(
        select(DecompiledFunction).where(DecompiledFunction.sample_id == sample.id)
    ))
    assert rows, "no functions persisted"
    decompiled = [r for r in rows if r.decompiled]
    assert decompiled, "nothing decompiled"
    assert all(r.code_sha256 for r in decompiled)
    # 42 + 1 == 0x2b: the decompilation is correct, not merely present.
    assert any("0x2b" in (r.decompiled or "") for r in decompiled)

    types = {f.type for f in findings_repo.for_case(session, case.id)}
    assert "decompilation_complete" in types
