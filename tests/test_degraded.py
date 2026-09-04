"""Optional native dependencies must never gate a decision.

TLSH, libmagic and LIEF are extras. A machine without a native toolchain -- CI,
a fresh laptop -- has to be able to ingest and identify a sample, or the
platform is only usable where it was built.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from necropsy.enums import Arch, FileType


@pytest.fixture
def no_tlsh(monkeypatch: pytest.MonkeyPatch):  # type: ignore[no-untyped-def]
    import necropsy.intake.hashing as hashing

    monkeypatch.setattr(hashing, "_HAVE_TLSH", False)
    monkeypatch.setattr(hashing, "_tlsh", None, raising=False)


@pytest.fixture
def no_magic(monkeypatch: pytest.MonkeyPatch):  # type: ignore[no-untyped-def]
    import necropsy.intake.identify as identify_mod

    monkeypatch.setattr(identify_mod, "_HAVE_MAGIC", False)


def test_hashing_without_tlsh(no_tlsh, pe_sample: Path) -> None:
    from necropsy.intake.hashing import hash_file, have_tlsh

    assert have_tlsh() is False
    hashes = hash_file(pe_sample)
    assert len(hashes.sha256) == 64
    assert hashes.tlsh is None


def test_identification_without_libmagic(no_magic, x86_packed_sample: Path) -> None:
    """Architecture and packing are answered by our own parser, not libmagic."""
    from necropsy.intake.identify import identify, is_probably_packed

    ident = identify(x86_packed_sample)
    assert ident.file_type is FileType.PE
    assert ident.arch is Arch.X86
    assert is_probably_packed(ident) is True
    assert ident.mime == "application/vnd.microsoft.portable-executable"


def test_full_pipeline_without_optional_deps(
    no_tlsh, no_magic, session, host, x86_packed_sample: Path
) -> None:
    from necropsy.cases import service as case_service
    from necropsy.db.repos import findings as findings_repo
    from necropsy.enums import JobState
    from necropsy.db.repos import jobs as jobs_repo
    from necropsy.intake import service as intake
    from necropsy.jobs.tasks.base import execute_job

    case = case_service.create_case(session, host, name="No native deps")
    session.commit()
    result = intake.ingest_file(session, host, case_id=case.id, src=x86_packed_sample)
    session.commit()
    execute_job(result.job_id)
    session.expire_all()

    assert jobs_repo.get(session, result.job_id).state is JobState.SUCCEEDED
    assert "arch_mismatch_risk" in {f.type for f in findings_repo.for_case(session, case.id)}


def test_ssdeep_absence_is_not_an_error(monkeypatch: pytest.MonkeyPatch, pe_sample: Path) -> None:
    import necropsy.intake.hashing as hashing

    monkeypatch.setattr(hashing.shutil, "which", lambda _: None)
    assert hashing.ssdeep_file(pe_sample) is None
