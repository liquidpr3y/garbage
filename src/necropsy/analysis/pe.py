"""Deep PE parsing.

LIEF when available, our own Phase 1 parser as the floor. The split matters:
the Phase 1 parser answers architecture and signature presence, which gate
decisions and must work with no native toolchain. Everything here is richer
detail -- imports, per-section entropy, TLS callbacks, debug paths, overlay --
which improves findings but never gates one.
"""

from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import lief

    lief.logging.disable()
    _HAVE_LIEF = True
except ImportError:  # pragma: no cover - exercised by the degraded-path test
    _HAVE_LIEF = False

# A section that is both writable and executable is the classic self-modifying
# unpacking stub. Legitimate compilers do not emit one.
WX = ("MEM_WRITE", "MEM_EXECUTE")

SECTION_ENTROPY_PACKED = 7.0
FEW_IMPORTS_THRESHOLD = 12


@dataclass
class SectionInfo:
    name: str
    virtual_size: int
    raw_size: int
    entropy: float
    characteristics: list[str]
    writable: bool
    executable: bool

    @property
    def write_execute(self) -> bool:
        return self.writable and self.executable


@dataclass
class PEInfo:
    parsed_with: str = "none"
    imphash: str | None = None
    imports: dict[str, list[str]] = field(default_factory=dict)
    exports: list[str] = field(default_factory=list)
    sections: list[SectionInfo] = field(default_factory=list)
    entrypoint_rva: int | None = None
    entrypoint_section: str | None = None
    tls_callbacks: list[int] = field(default_factory=list)
    pdb_path: str | None = None
    overlay_size: int = 0
    overlay_entropy: float | None = None
    signed: bool = False
    signature_subjects: list[str] = field(default_factory=list)
    is_dll: bool = False
    resource_count: int = 0
    error: str | None = None

    @property
    def imported_functions(self) -> list[str]:
        return [fn for fns in self.imports.values() for fn in fns]

    @property
    def import_count(self) -> int:
        return len(self.imported_functions)

    def to_dict(self) -> dict[str, Any]:
        return {
            "parsed_with": self.parsed_with,
            "imphash": self.imphash,
            "imports": self.imports,
            "import_count": self.import_count,
            "exports": self.exports[:200],
            "sections": [
                {
                    "name": s.name,
                    "virtual_size": s.virtual_size,
                    "raw_size": s.raw_size,
                    "entropy": round(s.entropy, 4),
                    "write_execute": s.write_execute,
                    "characteristics": s.characteristics,
                }
                for s in self.sections
            ],
            "entrypoint_rva": self.entrypoint_rva,
            "entrypoint_section": self.entrypoint_section,
            "tls_callbacks": len(self.tls_callbacks),
            "pdb_path": self.pdb_path,
            "overlay_size": self.overlay_size,
            "overlay_entropy": self.overlay_entropy,
            "signed": self.signed,
            "signature_subjects": self.signature_subjects,
            "is_dll": self.is_dll,
            "resource_count": self.resource_count,
            "error": self.error,
        }


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def parse(path: Path) -> PEInfo:
    if not _HAVE_LIEF:
        return PEInfo(parsed_with="none", error="LIEF not installed")
    try:
        binary = lief.PE.parse(str(path))
    except Exception as exc:  # noqa: BLE001 - a malformed PE is data, not a crash
        return PEInfo(parsed_with="lief", error=f"{type(exc).__name__}: {exc}")
    if binary is None:
        return PEInfo(parsed_with="lief", error="LIEF could not parse this file as a PE")

    info = PEInfo(parsed_with="lief")
    try:
        _fill(info, binary, path)
    except Exception as exc:  # noqa: BLE001
        info.error = f"partial parse: {type(exc).__name__}: {exc}"
    return info


def _fill(info: PEInfo, binary: Any, path: Path) -> None:
    for section in binary.sections:
        chars = [str(c).rsplit(".", 1)[-1] for c in section.characteristics_lists]
        info.sections.append(
            SectionInfo(
                name=section.name,
                virtual_size=section.virtual_size,
                raw_size=section.sizeof_raw_data,
                entropy=section.entropy,
                characteristics=chars,
                writable="MEM_WRITE" in chars,
                executable="MEM_EXECUTE" in chars,
            )
        )

    info.imports = {
        imp.name: [e.name for e in imp.entries if e.name] for imp in binary.imports
    }
    try:
        info.imphash = lief.PE.get_imphash(binary, lief.PE.IMPHASH_MODE.PEFILE) or None
    except Exception:  # noqa: BLE001
        info.imphash = None

    if binary.has_exports:
        info.exports = [e.name for e in binary.get_export().entries if e.name]

    info.entrypoint_rva = binary.optional_header.addressof_entrypoint
    info.entrypoint_section = _section_for_rva(info.sections, binary, info.entrypoint_rva)
    info.is_dll = binary.header.has_characteristic(lief.PE.Header.CHARACTERISTICS.DLL)

    if binary.has_tls and binary.tls is not None:
        info.tls_callbacks = [int(cb) for cb in binary.tls.callbacks]

    for entry in getattr(binary, "debug", []) or []:
        filename = getattr(entry, "filename", None)
        if filename:
            info.pdb_path = str(filename)
            break

    overlay = bytes(binary.overlay)
    info.overlay_size = len(overlay)
    if overlay:
        info.overlay_entropy = round(_entropy(overlay[: 1024 * 1024]), 4)

    info.signed = bool(binary.has_signatures)
    if info.signed:
        for signature in binary.signatures:
            for signer in signature.signers:
                subject = getattr(signer, "issuer", None)
                if subject:
                    info.signature_subjects.append(str(subject))

    if binary.has_resources:
        info.resource_count = _count_resources(binary.resources)


def _section_for_rva(sections: list[SectionInfo], binary: Any, rva: int | None) -> str | None:
    if rva is None:
        return None
    for section in binary.sections:
        if section.virtual_address <= rva < section.virtual_address + max(
            section.virtual_size, section.sizeof_raw_data
        ):
            return section.name
    return None


def _count_resources(node: Any, depth: int = 0) -> int:
    if depth > 6:
        return 0
    children = list(getattr(node, "childs", []) or [])
    if not children:
        return 1
    return sum(_count_resources(child, depth + 1) for child in children)


def have_lief() -> bool:
    return _HAVE_LIEF
