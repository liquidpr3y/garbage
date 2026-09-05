"""VMware Fusion detonation target, driven by the `vmrun` CLI.

Sequence per run: revert to the clean snapshot, boot, wait for VMware Tools,
push the sample, launch it, observe for a fixed window, screenshot, collect,
hard stop, revert.

Two things this deliberately does not do:

* It does not reconfigure the guest network to grant egress. VMware networking
  is a host-level configuration, and a tool that claimed to control it while
  silently failing would produce a quiet run that an operator reads as "the
  sample did nothing". Egress therefore requires a separately configured
  snapshot, and asking for it without one is an error, not a downgrade.
* It never logs the guest password, which appears in `vmrun` argv.
"""

from __future__ import annotations

import logging
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

from necropsy.enums import Arch
from necropsy.sandbox.targets.base import (
    CollectedFile,
    DetonationTarget,
    EgressUnavailable,
    ExecResult,
    GuestTimeout,
    NoTargetConfigured,
    TargetCapabilities,
    TargetError,
    TargetFingerprint,
)

log = logging.getLogger(__name__)

REDACTED = "***"


def _redact(argv: list[str]) -> str:
    """Render argv for logs with the guest password removed."""
    out: list[str] = []
    skip = False
    for token in argv:
        if skip:
            out.append(REDACTED)
            skip = False
            continue
        out.append(token)
        if token == "-gp":
            skip = True
    return " ".join(out)


class VMwareFusionTarget(DetonationTarget):
    def __init__(
        self,
        *,
        vmrun: str,
        vmx: Path,
        snapshot: str,
        guest_user: str,
        guest_password: str,
        guest_workdir: str,
        arch: Arch,
        guest_os: str = "windows",
        has_sysmon: bool = True,
        supports_egress: bool = False,
        boot_timeout_s: int = 240,
        command_timeout_s: int = 120,
        # How long after launch to check the process is alive, and how often to
        # poll for VMware Tools. Injectable so tests do not pay real seconds.
        liveness_probe_delay_s: float = 5.0,
        tools_poll_interval_s: float = 5.0,
        guest_hostname: str | None = None,
        egress: bool = False,
    ) -> None:
        if egress and not supports_egress:
            raise EgressUnavailable(
                "Egress-permitted detonation was requested, but no egress snapshot is "
                "configured (NECROPSY_SANDBOX_SNAPSHOT_EGRESS). Refusing to run "
                "isolated and report it as an egress run -- a quiet result would be "
                "unreadable. Configure the snapshot or accept the isolated proposal."
            )

        self._vmrun = vmrun
        self._vmx = vmx
        self._guest_user = guest_user
        self._guest_password = guest_password
        self._boot_timeout_s = boot_timeout_s
        self._command_timeout_s = command_timeout_s
        self._liveness_probe_delay_s = liveness_probe_delay_s
        self._tools_poll_interval_s = tools_poll_interval_s
        self._guest_hostname = guest_hostname
        self._prepared = False
        self._pending: list[CollectedFile] = []

        self.caps = TargetCapabilities(
            name="vmware-fusion",
            arch=arch,
            os=guest_os,
            has_sysmon=has_sysmon,
            supports_egress=supports_egress,
            snapshot=snapshot,
            guest_workdir=guest_workdir,
        )
        self._egress = egress

    # -- construction -------------------------------------------------------

    @classmethod
    def from_settings(cls, settings: Any, *, egress: bool = False) -> VMwareFusionTarget:
        if not settings.sandbox_vmx_path:
            raise NoTargetConfigured("NECROPSY_SANDBOX_VMX_PATH is not set")
        vmx = Path(settings.sandbox_vmx_path).expanduser()
        if not vmx.exists():
            raise NoTargetConfigured(f"VM not found at {vmx}")
        if not settings.sandbox_guest_user or not settings.sandbox_guest_password:
            raise NoTargetConfigured(
                "NECROPSY_SANDBOX_GUEST_USER and NECROPSY_SANDBOX_GUEST_PASSWORD are "
                "required; vmrun needs them to talk to VMware Tools in the guest"
            )

        egress_snapshot = settings.sandbox_snapshot_egress
        snapshot = (
            egress_snapshot if (egress and egress_snapshot) else settings.sandbox_snapshot_isolated
        )
        if not snapshot:
            raise NoTargetConfigured("NECROPSY_SANDBOX_SNAPSHOT_ISOLATED is not set")

        return cls(
            vmrun=settings.vmrun_path or "vmrun",
            vmx=vmx,
            snapshot=snapshot,
            guest_user=settings.sandbox_guest_user,
            guest_password=settings.sandbox_guest_password,
            guest_workdir=settings.sandbox_guest_workdir,
            arch=Arch(settings.sandbox_guest_arch),
            guest_os=settings.sandbox_guest_os,
            supports_egress=bool(egress_snapshot),
            boot_timeout_s=settings.sandbox_boot_timeout_s,
            guest_hostname=settings.sandbox_guest_hostname,
            egress=egress,
        )

    # -- vmrun plumbing -----------------------------------------------------

    def _run(
        self, command: list[str], *, auth: bool = False, timeout: int | None = None
    ) -> subprocess.CompletedProcess[str]:
        argv = [self._vmrun, "-T", "fusion"]
        if auth:
            argv += ["-gu", self._guest_user, "-gp", self._guest_password]
        argv += command
        log.debug("vmrun: %s", _redact(argv))
        try:
            return subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=timeout or self._command_timeout_s,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise GuestTimeout(f"vmrun timed out: {_redact(argv)}") from exc
        except FileNotFoundError as exc:
            raise NoTargetConfigured(
                f"vmrun not found at {self._vmrun!r}; set NECROPSY_VMRUN_PATH"
            ) from exc

    def _must(self, command: list[str], *, auth: bool = False, timeout: int | None = None) -> str:
        proc = self._run(command, auth=auth, timeout=timeout)
        if proc.returncode != 0:
            raise TargetError(
                f"vmrun {command[0]} failed ({proc.returncode}): "
                f"{(proc.stderr or proc.stdout).strip()[:300]}"
            )
        return proc.stdout

    # -- lifecycle ----------------------------------------------------------

    def prepare(self) -> None:
        self._must(["revertToSnapshot", str(self._vmx), self.caps.snapshot], timeout=300)
        self._must(["start", str(self._vmx), "nogui"], timeout=300)
        self._wait_for_tools()
        self._prepared = True

    def _wait_for_tools(self) -> None:
        deadline = time.monotonic() + self._boot_timeout_s
        while time.monotonic() < deadline:
            proc = self._run(["checkToolsState", str(self._vmx)], timeout=60)
            if "running" in (proc.stdout or "").lower():
                return
            time.sleep(self._tools_poll_interval_s)
        raise GuestTimeout(
            f"VMware Tools did not come up within {self._boot_timeout_s}s. The guest "
            "needs Tools installed for vmrun to reach it."
        )

    def push(self, local: Path, guest_name: str) -> PurePosixPath:
        guest_path = PureWindowsPath(self.caps.guest_workdir) / guest_name
        self._must(
            ["copyFileFromHostToGuest", str(self._vmx), str(local), str(guest_path)],
            auth=True,
            timeout=300,
        )
        return PurePosixPath(str(guest_path))

    def execute(self, guest_path: str, args: list[str], timeout_s: float) -> ExecResult:
        """Launch and observe for a fixed window.

        `-noWait` on purpose: a detonation is observed for a set period, not run
        to completion. Malware that never exits would otherwise hang the job,
        and malware that exits instantly is itself a result worth recording.
        """
        started = datetime.now(timezone.utc)
        self._must(
            ["runProgramInGuest", str(self._vmx), "-noWait", "-activeWindow", guest_path, *args],
            auth=True,
        )

        probe_at = min(self._liveness_probe_delay_s, timeout_s)
        time.sleep(probe_at)
        still_running = self._is_running(Path(guest_path).name)

        remaining = max(0.0, timeout_s - probe_at)
        if remaining:
            time.sleep(remaining)

        finished = datetime.now(timezone.utc)
        self._capture_screen()

        return ExecResult(
            exit_code=None,
            started_at=started,
            finished_at=finished,
            timed_out=False,
            detail=(
                "launched with -noWait and observed for the full window; "
                + (f"process was alive {probe_at:g}s after launch" if still_running
                   else f"process was NOT alive {probe_at:g}s after launch -- it exited, "
                        "crashed, or "
                        "refused to run (check the emulation fidelity of this pairing)")
            ),
        )

    def _is_running(self, image_name: str) -> bool:
        proc = self._run(["listProcessesInGuest", str(self._vmx)], auth=True)
        return image_name.lower() in (proc.stdout or "").lower()

    def _capture_screen(self) -> None:
        import tempfile

        out = Path(tempfile.mkstemp(suffix=".png")[1])
        try:
            proc = self._run(["captureScreen", str(self._vmx), str(out)], auth=True)
            if proc.returncode == 0 and out.exists() and out.stat().st_size:
                self._pending.append(
                    CollectedFile(name="screen.png", data=out.read_bytes(), kind="screenshot")
                )
        except TargetError:
            log.debug("screen capture unavailable")
        finally:
            out.unlink(missing_ok=True)

    def collect(self) -> list[CollectedFile]:
        collected, self._pending = self._pending, []
        return collected

    def revert(self) -> None:
        """Always safe to call, never raises. See DetonationTarget."""
        for command, kwargs in (
            (["stop", str(self._vmx), "hard"], {"timeout": 180}),
            (["revertToSnapshot", str(self._vmx), self.caps.snapshot], {"timeout": 300}),
        ):
            try:
                self._run(command, **kwargs)  # type: ignore[arg-type]
            except Exception as exc:  # noqa: BLE001 - teardown must not mask the real error
                log.error("sandbox teardown step %s failed: %s", command[0], exc)
        self._prepared = False

    def fingerprint(self, *, sample_arch: Arch, native_code: bool) -> TargetFingerprint:
        return TargetFingerprint(
            target=self.caps.name,
            arch=self.caps.arch.value,
            os=self.caps.os,
            snapshot=self.caps.snapshot,
            egress=self._egress,
            fidelity=self.caps.fidelity_for(sample_arch, native_code).value,
            tool_versions={"vmrun": self._vmrun_version()},
        )

    def _vmrun_version(self) -> str:
        try:
            proc = self._run([], timeout=30)
            first = (proc.stdout or "").strip().splitlines()
            return first[0] if first else "unknown"
        except Exception:  # noqa: BLE001
            return "unknown"

    @property
    def guest_hostname(self) -> str | None:
        return self._guest_hostname
