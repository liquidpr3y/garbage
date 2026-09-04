from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from necropsy.cases import service as case_service
from necropsy.db.models import AuditEvent
from necropsy.db.repos import samples as samples_repo
from necropsy.enums import SampleSource
from necropsy.intake import service as intake
from necropsy.intake.service import IngestError, SampleTooLarge


def _case(session, host, name="Case A"):  # type: ignore[no-untyped-def]
    case = case_service.create_case(session, host, name=name)
    session.commit()
    return case


def test_ingest_hashes_and_vaults(session, host, pe_sample: Path) -> None:
    case = _case(session, host)
    result = intake.ingest_file(
        session, host, case_id=case.id, src=pe_sample, enqueue=False
    )
    session.commit()

    expected = hashlib.sha256(pe_sample.read_bytes()).hexdigest()
    assert result.sample.sha256 == expected
    assert result.sample.size == pe_sample.stat().st_size
    assert result.sample_created is True

    vault = intake.open_vault(session, actor="test")
    assert vault.exists(expected)
    assert vault.read_bytes(expected) == pe_sample.read_bytes()


def test_same_sample_in_two_cases_is_one_vault_object(session, host, pe_sample: Path) -> None:
    first = _case(session, host, "First sighting")
    second = _case(session, host, "Second sighting")

    a = intake.ingest_file(session, host, case_id=first.id, src=pe_sample, enqueue=False)
    b = intake.ingest_file(session, host, case_id=second.id, src=pe_sample, enqueue=False)
    session.commit()

    assert a.sample.id == b.sample.id, "one set of bytes must be one sample row"
    assert b.sample_created is False
    assert b.other_case_count == 1

    assert len(samples_repo.for_case(session, first.id)) == 1
    assert len(samples_repo.for_case(session, second.id)) == 1

    vault_root = intake.open_vault(session, actor="t").root
    stored = list(vault_root.rglob("*.bin"))
    assert len(stored) == 1, "the same bytes must not be stored twice"


def test_reingest_into_the_same_case_is_idempotent(session, host, pe_sample: Path) -> None:
    case = _case(session, host)
    intake.ingest_file(session, host, case_id=case.id, src=pe_sample, enqueue=False)
    second = intake.ingest_file(session, host, case_id=case.id, src=pe_sample, enqueue=False)
    session.commit()
    assert second.attached is False
    assert len(samples_repo.for_case(session, case.id)) == 1


def test_ingest_writes_an_audit_trail(session, host, pe_sample: Path) -> None:
    case = _case(session, host)
    intake.ingest_file(session, host, case_id=case.id, src=pe_sample, enqueue=False)
    session.commit()

    actions = [e.action for e in session.query(AuditEvent).all()]
    assert "case.created" in actions
    assert "sample.ingested" in actions
    assert "vault.write" in actions


def test_observed_filename_is_per_case(session, host, tmp_path: Path, pe_sample: Path) -> None:
    """The same bytes arrive under different names; both names are kept."""
    case_a = _case(session, host, "A")
    case_b = _case(session, host, "B")
    renamed = tmp_path / "invoice_scan.exe"
    renamed.write_bytes(pe_sample.read_bytes())

    intake.ingest_file(session, host, case_id=case_a.id, src=pe_sample, enqueue=False)
    intake.ingest_file(
        session, host, case_id=case_b.id, src=renamed, source=SampleSource.PATH, enqueue=False
    )
    session.commit()

    names = {
        samples_repo.for_case(session, case_a.id)[0].observed_filename,
        samples_repo.for_case(session, case_b.id)[0].observed_filename,
    }
    assert names == {"invoice.exe", "invoice_scan.exe"}


def test_empty_file_is_refused(session, host, tmp_path: Path) -> None:
    case = _case(session, host)
    empty = tmp_path / "empty.bin"
    empty.write_bytes(b"")
    with pytest.raises(IngestError):
        intake.ingest_file(session, host, case_id=case.id, src=empty, enqueue=False)


def test_oversized_file_is_refused(session, host, tmp_path: Path, monkeypatch) -> None:
    from necropsy.config import get_settings

    case = _case(session, host)
    big = tmp_path / "big.bin"
    big.write_bytes(b"\x00" * 4096)
    monkeypatch.setattr(get_settings(), "max_sample_bytes", 1024)
    with pytest.raises(SampleTooLarge):
        intake.ingest_file(session, host, case_id=case.id, src=big, enqueue=False)


def test_unknown_case_is_refused(session, host, pe_sample: Path) -> None:
    with pytest.raises(intake.CaseNotFound):
        intake.ingest_file(session, host, case_id="nope", src=pe_sample, enqueue=False)


def test_missing_vault_object_is_re_vaulted(session, host, pe_sample: Path) -> None:
    """XProtect eating a sample must not leave a case pointing at nothing."""
    case = _case(session, host)
    first = intake.ingest_file(session, host, case_id=case.id, src=pe_sample, enqueue=False)
    session.commit()

    vault = intake.open_vault(session, actor="t")
    target = vault.path_for(first.sample.sha256)
    target.chmod(0o600)
    target.unlink()
    assert not vault.exists(first.sample.sha256)

    other = _case(session, host, "Later case")
    intake.ingest_file(session, host, case_id=other.id, src=pe_sample, enqueue=False)
    session.commit()
    assert vault.exists(first.sample.sha256)
