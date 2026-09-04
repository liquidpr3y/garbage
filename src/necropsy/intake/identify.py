"""File identification: type, architecture, entropy, format specifics.

Deliberately pure-Python for the parts that matter. Architecture and PE
signature presence gate real decisions (Phase 3 target matching, the
pe_no_signature finding), so they must work on a machine with no native
toolchain -- which is also what keeps CI honest. libmagic and LIEF, when
installed, add descriptive detail on top; they never gate a decision.
"""

from __future__ import annotations

import math
import struct
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from necropsy.enums import Arch, FileType

try:  # optional: pip install necropsy[analysis]
    import magic as _magic

    _HAVE_MAGIC = True
except ImportError:  # pragma: no cover
    _HAVE_MAGIC = False

# Entropy over the whole file is misleading for very large samples and slow for
# no benefit; the leading window is what packers actually affect.
ENTROPY_WINDOW = 16 * 1024 * 1024

# Above this, a PE's contents are compressed, encrypted or packed. 7.2 is the
# conventional triage threshold: high enough to skip ordinary compiled code,
# low enough to catch most packers.
PACKED_ENTROPY_THRESHOLD = 7.2

_PE_MACHINE = {
    0x014C: Arch.X86,
    0x8664: Arch.X86_64,
    0xAA64: Arch.ARM64,
    0x01C0: Arch.ARM,
    0x01C4: Arch.ARM,  # ARMNT (Thumb-2)
    0x0200: Arch.UNKNOWN,  # IA64, not something we will ever detonate
}

_ELF_MACHINE = {
    0x03: Arch.X86,
    0x3E: Arch.X86_64,
    0x28: Arch.ARM,
    0xB7: Arch.ARM64,
}

_MACHO_CPU = {
    7: Arch.X86,
    0x01000007: Arch.X86_64,
    12: Arch.ARM,
    0x0100000C: Arch.ARM64,
}


@dataclass
class Identity:
    file_type: FileType = FileType.UNKNOWN
    arch: Arch = Arch.UNKNOWN
    mime: str | None = None
    magic: str | None = None
    entropy: float | None = None
    detail: dict[str, Any] = field(default_factory=dict)


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def identify(path: Path) -> Identity:
    head = path.read_bytes()[:4096] if path.stat().st_size < 4096 else _read(path, 4096)
    ident = Identity()

    ident.entropy = round(shannon_entropy(_read(path, ENTROPY_WINDOW)), 4)

    if _HAVE_MAGIC:
        try:
            ident.magic = _magic.from_file(str(path))
            ident.mime = _magic.from_file(str(path), mime=True)
        except Exception:  # noqa: BLE001 - libmagic failure must never block intake
            pass

    ident.file_type, ident.arch, detail = _classify(path, head)
    ident.detail.update(detail)

    if ident.mime is None:
        ident.mime = _FALLBACK_MIME.get(ident.file_type)
    return ident


_FALLBACK_MIME = {
    FileType.PE: "application/vnd.microsoft.portable-executable",
    FileType.ELF: "application/x-elf",
    FileType.MACHO: "application/x-mach-binary",
    FileType.PDF: "application/pdf",
    FileType.ARCHIVE: "application/zip",
    FileType.SCRIPT: "text/plain",
}


def _read(path: Path, n: int) -> bytes:
    with path.open("rb") as fh:
        return fh.read(n)


def _classify(path: Path, head: bytes) -> tuple[FileType, Arch, dict[str, Any]]:
    if head[:2] == b"MZ":
        return _classify_pe(path, head)
    if head[:4] == b"\x7fELF":
        return FileType.ELF, _elf_arch(head), {}
    if head[:4] in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe"):
        return FileType.MACHO, _macho_arch(head), {}
    if head[:4] == b"\xca\xfe\xba\xbe":
        return FileType.MACHO, Arch.MIXED, {"universal_binary": True}
    if head[:4] == b"%PDF":
        return FileType.PDF, Arch.NOT_APPLICABLE, {}
    if head[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        # OLE compound file: legacy Office, and also MSI.
        return FileType.OFFICE, Arch.NOT_APPLICABLE, {"container": "ole"}
    if head[:4] == b"PK\x03\x04":
        return _classify_zip(path)
    if head[:8] == b"L\x00\x00\x00\x01\x14\x02\x00":
        # Windows shortcut. Worth its own type: LNK-based delivery is common and
        # detonates faithfully on ARM, so it is squarely in scope for the POC lab.
        return FileType.SHORTCUT, Arch.NOT_APPLICABLE, {}
    if head[:2] in (b"#!", b"\xef\xbb") or _looks_textual(head):
        return FileType.SCRIPT, Arch.NOT_APPLICABLE, {}
    if head[:2] == b"\x1f\x8b" or head[:4] in (b"Rar!", b"7z\xbc\xaf"):
        return FileType.ARCHIVE, Arch.NOT_APPLICABLE, {}
    return FileType.UNKNOWN, Arch.UNKNOWN, {}


def _looks_textual(head: bytes) -> bool:
    if not head:
        return False
    sample = head[:1024]
    if b"\x00" in sample:
        return False
    printable = sum(1 for b in sample if 0x20 <= b < 0x7F or b in (0x09, 0x0A, 0x0D))
    return printable / len(sample) > 0.95


def _classify_zip(path: Path) -> tuple[FileType, Arch, dict[str, Any]]:
    import zipfile

    try:
        with zipfile.ZipFile(path) as zf:
            names = zf.namelist()[:200]
    except (zipfile.BadZipFile, OSError):
        return FileType.ARCHIVE, Arch.NOT_APPLICABLE, {}

    if any(n.startswith(("word/", "xl/", "ppt/")) for n in names):
        has_macro = any("vbaProject" in n for n in names)
        return (
            FileType.OFFICE,
            Arch.NOT_APPLICABLE,
            {"container": "ooxml", "has_vba_macro": has_macro},
        )
    return FileType.ARCHIVE, Arch.NOT_APPLICABLE, {"entry_count": len(names)}


def _elf_arch(head: bytes) -> Arch:
    if len(head) < 20:
        return Arch.UNKNOWN
    machine = struct.unpack_from("<H", head, 18)[0]
    return _ELF_MACHINE.get(machine, Arch.UNKNOWN)


def _macho_arch(head: bytes) -> Arch:
    if len(head) < 8:
        return Arch.UNKNOWN
    cputype = struct.unpack_from("<I", head, 4)[0]
    return _MACHO_CPU.get(cputype, Arch.UNKNOWN)


def _classify_pe(path: Path, head: bytes) -> tuple[FileType, Arch, dict[str, Any]]:
    """Parse enough of the PE to answer the questions Phase 1 actually asks.

    Namely: what architecture is this (does our lab run it?) and is it
    Authenticode-signed (an unsigned executable is not damning, but an unsigned
    executable claiming to be a vendor binary is worth a finding).
    """
    detail: dict[str, Any] = {"format": "pe"}
    try:
        data = _read(path, 1024 * 1024)
        if len(data) < 0x40:
            return FileType.PE, Arch.UNKNOWN, detail

        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if e_lfanew + 24 > len(data) or data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
            # MZ with no PE header: DOS executable or a truncated/corrupt file.
            detail["pe_header"] = "missing"
            return FileType.PE, Arch.X86, detail

        coff = e_lfanew + 4
        machine, n_sections, timestamp = struct.unpack_from("<HHI", data, coff)
        size_opt = struct.unpack_from("<H", data, coff + 16)[0]
        characteristics = struct.unpack_from("<H", data, coff + 18)[0]

        arch = _PE_MACHINE.get(machine, Arch.UNKNOWN)
        detail.update(
            {
                "machine": hex(machine),
                "sections": n_sections,
                "timestamp": timestamp,
                "is_dll": bool(characteristics & 0x2000),
                "characteristics": hex(characteristics),
            }
        )

        opt = coff + 20
        if opt + 2 > len(data):
            return FileType.PE, arch, detail
        opt_magic = struct.unpack_from("<H", data, opt)[0]
        pe32_plus = opt_magic == 0x20B
        detail["pe32_plus"] = pe32_plus

        if opt + 72 <= len(data):
            detail["subsystem"] = struct.unpack_from("<H", data, opt + 68)[0]
            detail["dll_characteristics"] = struct.unpack_from("<H", data, opt + 70)[0]

        # NumberOfRvaAndSizes sits after the windows-specific fields, whose size
        # differs between PE32 and PE32+ (8-byte stack/heap fields).
        n_rva_off = opt + (108 if pe32_plus else 92)
        dirs_off = opt + (112 if pe32_plus else 96)
        if n_rva_off + 4 <= len(data):
            n_rva = struct.unpack_from("<I", data, n_rva_off)[0]
            # Data directory index 4 is the certificate table.
            if n_rva > 4 and dirs_off + 40 <= len(data):
                cert_rva, cert_size = struct.unpack_from("<II", data, dirs_off + 32)
                detail["authenticode_signed"] = cert_size > 0
                detail["certificate_size"] = cert_size

        detail["section_names"] = _pe_section_names(data, opt + size_opt, n_sections)
    except (struct.error, IndexError, OSError, ValueError) as exc:
        # Malformed headers are themselves interesting, and a parse failure must
        # never fail an ingest -- the bytes are already safely vaulted.
        detail["parse_error"] = f"{type(exc).__name__}: {exc}"
        return FileType.PE, Arch.UNKNOWN, detail

    return FileType.PE, arch, detail


def _pe_section_names(data: bytes, offset: int, count: int) -> list[str]:
    names: list[str] = []
    for i in range(min(count, 64)):
        start = offset + i * 40
        if start + 8 > len(data):
            break
        raw = data[start : start + 8].rstrip(b"\x00")
        names.append(raw.decode("latin-1", errors="replace"))
    return names


def is_probably_packed(ident: Identity) -> bool:
    return (
        ident.file_type is FileType.PE
        and ident.entropy is not None
        and ident.entropy >= PACKED_ENTROPY_THRESHOLD
    )


def have_magic() -> bool:
    return _HAVE_MAGIC
