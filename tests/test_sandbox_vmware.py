"""The VMware target, driven through a stub `vmrun`.

VMware Fusion is not present in CI and never will be, so the stub records the
argv it is handed and replies the way vmrun does. That verifies the parts that
are actually ours -- command construction, ordering, the boot wait, teardown,
password redaction -- and leaves only Fusion's own behaviour untested. The
sequence still deserves one live run on the analysis Mac before it is trusted
with a real sample.
"""

from __future__ import annotations

import stat
from pathlib import Path

import pytest

from necropsy.enums import Arch
from necropsy.sandbox.targets.base import GuestTimeout, TargetError
from necropsy.sandbox.targets.vmware import VMwareFusionTarget

STUB = """#!/bin/sh
echo "$@" >> "{log}"
case "$*" in
  *checkToolsState*)   echo "{tools}" ;;
  *listProcessesInGuest*) echo "pid=4444, owner=analyst, cmd=sample_deadbeef.exe" ;;
  *captureScreen*)     printf '\\211PNG\\r\\n\\032\\n fake' > "$(eval echo \\${{$#}})" ;;
  *revertToSnapshot*)  {revert} ;;
  *)                   : ;;
esac
exit 0
"""


def _stub(tmp_path: Path, *, tools: str = "running", revert: str = ":") -> tuple[Path, Path]:
    log = tmp_path / "vmrun.log"
    script = tmp_path / "vmrun"
    script.write_text(STUB.format(log=log, tools=tools, revert=revert))
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    return script, log


def _target(tmp_path: Path, script: Path, **kw) -> VMwareFusionTarget:  # type: ignore[no-untyped-def]
    vmx = tmp_path / "lab.vmx"
    vmx.write_text("# fake vm")
    defaults = dict(
        vmrun=str(script), vmx=vmx, snapshot="clean-arm64",
        guest_user="analyst", guest_password="s3cret",
        guest_workdir="C:\\Users\\Public", arch=Arch.ARM64,
        boot_timeout_s=10, guest_hostname="WIN-LAB-01",
        liveness_probe_delay_s=0.05, tools_poll_interval_s=0.05,
    )
    defaults.update(kw)
    return VMwareFusionTarget(**defaults)  # type: ignore[arg-type]


def test_prepare_reverts_then_boots_then_waits_for_tools(tmp_path: Path) -> None:
    script, log = _stub(tmp_path)
    _target(tmp_path, script).prepare()

    lines = log.read_text().strip().splitlines()
    assert "revertToSnapshot" in lines[0] and "clean-arm64" in lines[0]
    assert "start" in lines[1] and "nogui" in lines[1]
    assert "checkToolsState" in lines[2]


def test_boot_timeout_is_reported_clearly(tmp_path: Path) -> None:
    script, _log = _stub(tmp_path, tools="not installed")
    target = _target(tmp_path, script, boot_timeout_s=1)
    with pytest.raises(GuestTimeout, match="VMware Tools"):
        target.prepare()


def test_push_places_the_sample_in_the_guest_workdir(tmp_path: Path) -> None:
    script, log = _stub(tmp_path)
    local = tmp_path / "s.bin"
    local.write_bytes(b"inert")

    guest = _target(tmp_path, script).push(local, "sample_deadbeef.exe")
    assert "C:\\Users\\Public" in str(guest)
    assert "copyFileFromHostToGuest" in log.read_text()


def test_execute_launches_without_waiting_and_reports_liveness(tmp_path: Path) -> None:
    """A detonation is observed for a window, not run to completion."""
    script, log = _stub(tmp_path)
    result = _target(tmp_path, script).execute("C:\\Users\\Public\\sample_deadbeef.exe", [], 0.2)

    text = log.read_text()
    assert "runProgramInGuest" in text
    assert "-noWait" in text
    assert "listProcessesInGuest" in text
    assert result.exit_code is None
    assert "alive 0.05s after launch" in result.detail
    assert result.started_at and result.finished_at


def test_a_process_that_died_immediately_is_called_out(tmp_path: Path) -> None:
    """The distinction that matters most on an emulated pairing."""
    log = tmp_path / "vmrun.log"
    script = tmp_path / "vmrun"
    script.write_text(
        f'#!/bin/sh\necho "$@" >> "{log}"\n'
        'case "$*" in *checkToolsState*) echo running;; '
        '*listProcessesInGuest*) echo "pid=900, owner=analyst, cmd=explorer.exe";; esac\nexit 0\n'
    )
    script.chmod(script.stat().st_mode | stat.S_IEXEC)

    result = _target(tmp_path, script).execute("C:\\Users\\Public\\sample.exe", [], 0.2)
    assert "NOT alive" in result.detail
    assert "emulation fidelity" in result.detail


def test_screenshot_is_collected(tmp_path: Path) -> None:
    script, _log = _stub(tmp_path)
    target = _target(tmp_path, script)
    target.execute("C:\\Users\\Public\\s.exe", [], 0.2)

    collected = target.collect()
    assert [c.kind for c in collected] == ["screenshot"]
    assert collected[0].data.startswith(b"\x89PNG")
    assert target.collect() == [], "collect() must drain, not repeat"


def test_revert_stops_hard_then_restores(tmp_path: Path) -> None:
    script, log = _stub(tmp_path)
    _target(tmp_path, script).revert()

    lines = log.read_text().strip().splitlines()
    assert "stop" in lines[0] and "hard" in lines[0]
    assert "revertToSnapshot" in lines[1]


def test_revert_continues_after_a_failing_step(tmp_path: Path) -> None:
    """If stop fails, the snapshot restore must still be attempted."""
    log = tmp_path / "vmrun.log"
    script = tmp_path / "vmrun"
    script.write_text(
        f'#!/bin/sh\necho "$@" >> "{log}"\n'
        'case "$*" in *stop*) echo "boom" >&2; exit 255;; esac\nexit 0\n'
    )
    script.chmod(script.stat().st_mode | stat.S_IEXEC)

    _target(tmp_path, script).revert()
    assert "revertToSnapshot" in log.read_text()


def test_the_password_never_reaches_the_log_file_we_control(tmp_path: Path) -> None:
    """The stub logs argv, which is what a debug log would capture."""
    script, log = _stub(tmp_path)
    target = _target(tmp_path, script)
    local = tmp_path / "s.bin"
    local.write_bytes(b"x")
    target.push(local, "s.exe")

    # vmrun genuinely receives the password -- that is unavoidable. What must
    # never happen is Necropsy rendering it into its own logs.
    from necropsy.sandbox.targets.vmware import _redact

    assert "s3cret" not in _redact(
        [str(script), "-gu", "analyst", "-gp", "s3cret", "start", "x"]
    )


def test_missing_vmrun_is_a_configuration_error(tmp_path: Path) -> None:
    from necropsy.sandbox.targets.base import NoTargetConfigured

    target = _target(tmp_path, Path("/nonexistent/vmrun"))
    with pytest.raises(NoTargetConfigured, match="NECROPSY_VMRUN_PATH"):
        target.prepare()


def test_vmrun_failure_surfaces_its_stderr(tmp_path: Path) -> None:
    script = tmp_path / "vmrun"
    script.write_text('#!/bin/sh\necho "Error: snapshot not found" >&2\nexit 255\n')
    script.chmod(script.stat().st_mode | stat.S_IEXEC)

    with pytest.raises(TargetError, match="snapshot not found"):
        _target(tmp_path, script).prepare()


def test_fingerprint_records_what_the_run_ran_on(tmp_path: Path) -> None:
    script, _log = _stub(tmp_path)
    fingerprint = _target(tmp_path, script).fingerprint(sample_arch=Arch.X86, native_code=True)

    assert fingerprint.arch == "arm64"
    assert fingerprint.snapshot == "clean-arm64"
    assert fingerprint.fidelity == "emulated"
    assert fingerprint.egress is False
