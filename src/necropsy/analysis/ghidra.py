"""Ghidra headless driver.

Ghidra is Apache-2.0, so bundling or automating it is unencumbered, but it is
still driven as an external process because that is what `analyzeHeadless` is.
A run imports the sample into a throwaway project, analyses it, and runs
`ghidra_scripts/necropsy_export.py` to dump functions and decompiled C as JSON.

Read-only throughout. Ghidra never executes the sample; the emulator is not
enabled and no script here starts a process from the binary under analysis.

Unavailability is reported, not raised: an analyst on a laptop without Ghidra
installed still gets every other part of static triage.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from necropsy.config import get_settings

log = logging.getLogger(__name__)

SCRIPT_DIR = Path(__file__).parent / "ghidra_scripts"
SCRIPT_NAME = "necropsy_export.py"


class GhidraUnavailable(RuntimeError):
    pass


@dataclass
class GhidraResult:
    available: bool = True
    program: dict[str, Any] = field(default_factory=dict)
    functions: list[dict[str, Any]] = field(default_factory=list)
    total_functions: int = 0
    truncated: bool = False
    duration_s: float = 0.0
    stdout_tail: str = ""
    error: str | None = None

    def summary(self) -> dict[str, Any]:
        decompiled = sum(1 for f in self.functions if f.get("decompiled"))
        return {
            "available": self.available,
            "language": self.program.get("language"),
            "compiler": self.program.get("compiler"),
            "exported_functions": len(self.functions),
            "decompiled_functions": decompiled,
            "total_functions": self.total_functions,
            "truncated": self.truncated,
            "duration_s": round(self.duration_s, 1),
            "error": self.error,
        }


def headless_binary() -> Path | None:
    settings = get_settings()
    candidates: list[Path] = []
    if settings.ghidra_home:
        candidates.append(Path(settings.ghidra_home) / "support" / "analyzeHeadless")
    env_home = os.environ.get("GHIDRA_HOME") or os.environ.get("GHIDRA_INSTALL_DIR")
    if env_home:
        candidates.append(Path(env_home) / "support" / "analyzeHeadless")
    on_path = shutil.which("analyzeHeadless")
    if on_path:
        candidates.append(Path(on_path))
    for candidate in candidates:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate
    return None


def have_ghidra() -> bool:
    return headless_binary() is not None


def decompile(sample_path: Path, *, max_functions: int | None = None) -> GhidraResult:
    import time

    settings = get_settings()
    binary = headless_binary()
    if binary is None:
        return GhidraResult(
            available=False,
            error=(
                "Ghidra not found. Set NECROPSY_GHIDRA_HOME to the installation root "
                "(the directory containing support/analyzeHeadless)."
            ),
        )

    max_functions = max_functions or settings.ghidra_max_functions
    workdir = Path(tempfile.mkdtemp(prefix="necropsy-ghidra-"))
    project_dir = workdir / "project"
    project_dir.mkdir()
    out_json = workdir / "export.json"

    argv = [
        str(binary),
        str(project_dir),
        "necropsy",
        "-import", str(sample_path),
        "-scriptPath", str(SCRIPT_DIR),
        "-postScript", SCRIPT_NAME, str(out_json), str(max_functions),
        "-deleteProject",
        "-analysisTimeoutPerFile", str(settings.ghidra_timeout_s),
    ]

    started = time.monotonic()
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=settings.ghidra_timeout_s + 120,
            check=False,
            # A headless run must not inherit an interactive JVM configuration.
            env={**os.environ, "MAXMEM": os.environ.get("MAXMEM", "2G")},
        )
    except subprocess.TimeoutExpired:
        shutil.rmtree(workdir, ignore_errors=True)
        return GhidraResult(
            available=True,
            duration_s=time.monotonic() - started,
            error=f"Ghidra exceeded {settings.ghidra_timeout_s}s and was killed",
        )

    duration = time.monotonic() - started
    tail = "\n".join((proc.stdout or "").strip().splitlines()[-25:])

    try:
        if not out_json.exists():
            return GhidraResult(
                available=True,
                duration_s=duration,
                stdout_tail=tail,
                error=(
                    f"Ghidra exited {proc.returncode} without producing an export. "
                    f"stderr: {(proc.stderr or '').strip()[-400:]}"
                ),
            )
        payload = json.loads(out_json.read_text())
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    return GhidraResult(
        available=True,
        program=payload.get("program", {}),
        functions=payload.get("functions", []),
        total_functions=int(payload.get("total_functions", 0)),
        truncated=bool(payload.get("truncated", False)),
        duration_s=duration,
        stdout_tail=tail,
    )
