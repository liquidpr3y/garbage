"""Fast pre-triage via rizin, as an external process.

Rizin is LGPL-3, so it is invoked as a subprocess and never linked -- the same
stance as Nmap in the pentest module (docs/ARCHITECTURE.md S7).

This is enrichment, not a gate. Static triage produces a complete PE parse,
strings, capabilities and YARA results whether or not rizin is installed; what
rizin adds is cheap function discovery ahead of committing to an eight-minute
Ghidra pass. A missing binary is reported, never raised.

Field mapping note: rz-bin's JSON keys have shifted across releases, so every
lookup here is defensive and tolerates several shapes. Worth a smoke test
against the rizin build actually installed on the analysis Mac.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from necropsy.config import get_settings

log = logging.getLogger(__name__)


@dataclass
class RizinTriage:
    available: bool = False
    version: str | None = None
    function_count: int | None = None
    entrypoints: list[str] = field(default_factory=list)
    libraries: list[str] = field(default_factory=list)
    binary_info: dict[str, Any] = field(default_factory=dict)
    error: str | None = None

    def summary(self) -> dict[str, Any]:
        return {
            "available": self.available,
            "version": self.version,
            "function_count": self.function_count,
            "entrypoints": self.entrypoints[:8],
            "libraries": self.libraries[:60],
            "binary_info": self.binary_info,
            "error": self.error,
        }


def rizin_binary() -> str | None:
    configured = get_settings().rizin_path
    if configured:
        return configured if Path(configured).exists() else None
    return shutil.which("rizin") or shutil.which("rz-bin")


def _run(argv: list[str], timeout: int) -> tuple[int, str, str]:
    proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
    return proc.returncode, proc.stdout, proc.stderr


def triage(path: Path) -> RizinTriage:
    settings = get_settings()
    binary = rizin_binary()
    if not binary:
        return RizinTriage(available=False, error="rizin not found on PATH")

    result = RizinTriage(available=True)
    try:
        result.version = _version(binary, settings.rizin_timeout_s)
        result.binary_info = _bin_info(binary, path, settings.rizin_timeout_s)
        result.libraries = result.binary_info.pop("_libraries", [])
        result.entrypoints = result.binary_info.pop("_entrypoints", [])
        result.function_count = _function_count(binary, path, settings.rizin_timeout_s)
    except subprocess.TimeoutExpired:
        result.error = f"rizin timed out after {settings.rizin_timeout_s}s"
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        result.error = f"{type(exc).__name__}: {exc}"
    return result


def _version(binary: str, timeout: int) -> str | None:
    code, out, _err = _run([binary, "-v"], timeout)
    return out.strip().splitlines()[0] if code == 0 and out.strip() else None


def _bin_info(binary: str, path: Path, timeout: int) -> dict[str, Any]:
    """`rizin -qj -c 'ij; iej; ilj'` in one pass, tolerating key drift."""
    code, out, err = _run(
        [binary, "-q", "-e", "bin.cache=true", "-c", "ij", "-c", "iej", "-c", "ilj", str(path)],
        timeout,
    )
    if code != 0 and not out.strip():
        raise ValueError(f"rizin exited {code}: {err.strip()[:200]}")

    blobs = _json_objects(out)
    info: dict[str, Any] = {}
    libraries: list[str] = []
    entrypoints: list[str] = []

    for blob in blobs:
        if isinstance(blob, dict) and ("bin" in blob or "core" in blob):
            core = blob.get("core", {})
            binfo = blob.get("bin", {})
            info.update(
                {
                    "format": binfo.get("bintype") or core.get("format"),
                    "arch": binfo.get("arch"),
                    "bits": binfo.get("bits"),
                    "os": binfo.get("os"),
                    "compiler": binfo.get("compiler"),
                    "stripped": binfo.get("stripped"),
                    "canary": binfo.get("canary"),
                    "nx": binfo.get("nx"),
                    "pic": binfo.get("pic"),
                }
            )
        elif isinstance(blob, list):
            for item in blob:
                if isinstance(item, dict) and ("vaddr" in item or "paddr" in item):
                    vaddr = item.get("vaddr", item.get("paddr"))
                    if vaddr is not None:
                        entrypoints.append(hex(vaddr) if isinstance(vaddr, int) else str(vaddr))
                elif isinstance(item, str):
                    libraries.append(item)
                elif isinstance(item, dict) and "name" in item:
                    libraries.append(str(item["name"]))

    info = {k: v for k, v in info.items() if v is not None}
    info["_libraries"] = libraries
    info["_entrypoints"] = entrypoints
    return info


def _function_count(binary: str, path: Path, timeout: int) -> int | None:
    """Analyse and count functions. `aa` is the fast pass, not `aaaa`."""
    code, out, _err = _run([binary, "-q", "-c", "aa", "-c", "aflc", str(path)], timeout)
    if code != 0:
        return None
    for line in reversed(out.strip().splitlines()):
        token = line.strip()
        if token.isdigit():
            return int(token)
    return None


def _json_objects(text: str) -> list[Any]:
    """rizin emits one JSON document per -c; parse them line-wise and tolerantly."""
    blobs: list[Any] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line[0] not in "[{":
            continue
        try:
            blobs.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return blobs


def have_rizin() -> bool:
    return rizin_binary() is not None
