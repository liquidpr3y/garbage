from __future__ import annotations

from pathlib import Path

from conftest import make_pe

from necropsy.enums import Arch, FileType
from necropsy.intake.identify import identify, is_probably_packed


def test_pe_x86_64_unsigned(pe_sample: Path) -> None:
    ident = identify(pe_sample)
    assert ident.file_type is FileType.PE
    assert ident.arch is Arch.X86_64
    assert ident.detail["authenticode_signed"] is False
    assert ident.detail["pe32_plus"] is True
    assert ".text" in ident.detail["section_names"]


def test_pe_signature_detected(tmp_path: Path) -> None:
    ident = identify(make_pe(tmp_path / "signed.exe", signed=True))
    assert ident.detail["authenticode_signed"] is True
    assert ident.detail["certificate_size"] > 0


def test_pe_architectures(tmp_path: Path) -> None:
    cases = {0x014C: Arch.X86, 0x8664: Arch.X86_64, 0xAA64: Arch.ARM64, 0x01C4: Arch.ARM}
    for machine, expected in cases.items():
        ident = identify(make_pe(tmp_path / f"{machine:x}.exe", machine=machine))
        assert ident.arch is expected, f"machine {machine:#x}"


def test_packed_detection(x86_packed_sample: Path, pe_sample: Path) -> None:
    assert is_probably_packed(identify(x86_packed_sample)) is True
    assert is_probably_packed(identify(pe_sample)) is False


def test_ooxml_macro_detection(macro_doc: Path) -> None:
    ident = identify(macro_doc)
    assert ident.file_type is FileType.OFFICE
    assert ident.detail["has_vba_macro"] is True
    # Macro docs run through a native ARM64 interpreter, so no arch constraint.
    assert ident.arch is Arch.NOT_APPLICABLE


def test_script_and_pdf_and_lnk(tmp_path: Path) -> None:
    script = tmp_path / "dropper.ps1"
    script.write_text("#!/usr/bin/env pwsh\nWrite-Output 'inert'\n")
    assert identify(script).file_type is FileType.SCRIPT

    pdf = tmp_path / "doc.pdf"
    pdf.write_bytes(b"%PDF-1.7\n" + b"0" * 512)
    assert identify(pdf).file_type is FileType.PDF

    lnk = tmp_path / "invoice.lnk"
    lnk.write_bytes(b"L\x00\x00\x00\x01\x14\x02\x00" + b"\x00" * 256)
    assert identify(lnk).file_type is FileType.SHORTCUT


def test_malformed_pe_does_not_raise(tmp_path: Path) -> None:
    """A corrupt header is itself interesting; it must never fail an ingest."""
    broken = tmp_path / "broken.exe"
    broken.write_bytes(b"MZ" + b"\xff" * 200)
    ident = identify(broken)
    assert ident.file_type is FileType.PE


def test_unknown_binary(tmp_path: Path) -> None:
    blob = tmp_path / "mystery.dat"
    blob.write_bytes(bytes(range(256)) * 8)
    assert identify(blob).file_type is FileType.UNKNOWN
