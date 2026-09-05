"""The invariants that make dynamic analysis safe to have at all.

These are structural assertions, not behavioural ones. They exist because the
failure they guard against is silent: a localhost target added "just for
testing", a revert that stops happening on the error path, an egress request
quietly downgraded to isolated. Each would look fine in a passing test suite
and be catastrophic in use.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path

import pytest

from necropsy.enums import Arch
from necropsy.sandbox.targets import REGISTRY, build_target
from necropsy.sandbox.targets.base import (
    DetonationTarget,
    EgressUnavailable,
    EmulationFidelity,
    NoTargetConfigured,
    TargetCapabilities,
)
from necropsy.sandbox.targets.vmware import VMwareFusionTarget, _redact

SANDBOX_ROOT = Path(__file__).resolve().parents[1] / "src" / "necropsy" / "sandbox"


def test_no_localhost_target_exists() -> None:
    """There must be no way to execute a sample on this machine."""
    banned = ("localhost", "local_target", "hosttarget", "inprocess", "nativetarget")
    for module in SANDBOX_ROOT.rglob("*.py"):
        tree = ast.parse(module.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                name = node.name.lower()
                assert not any(b in name for b in banned), (
                    f"{module.name} defines {node.name}: a target that runs on the host "
                    "must never exist"
                )


def test_registry_lists_only_separate_machines() -> None:
    assert set(REGISTRY) == {"vmware", "remote"}


def test_sandbox_never_executes_the_sample_itself() -> None:
    """No module in the sandbox package may spawn the sample as a process.

    The sample only ever reaches a subprocess as an argument to vmrun, which
    copies it into a guest. Anything using subprocess must be a lab-control
    tool, not the sample.
    """
    allowed = {"vmrun", "tcpdump"}
    for module in SANDBOX_ROOT.rglob("*.py"):
        source = module.read_text()
        if "subprocess" not in source:
            continue
        assert any(tool in source for tool in allowed), (
            f"{module.name} runs a subprocess that is not a known lab-control tool"
        )


def test_detonation_is_disabled_by_default(settings) -> None:  # type: ignore[no-untyped-def]
    """Nothing detonates because a VM path happened to be configured."""
    assert settings.sandbox_enabled is False
    with pytest.raises(NoTargetConfigured, match="NECROPSY_SANDBOX_ENABLED"):
        build_target()


def test_egress_request_without_an_egress_snapshot_is_refused() -> None:
    """Refusing beats silently detonating isolated.

    An operator who asked for live C2 contact and got an isolated run would
    read the resulting silence as the sample doing nothing.
    """
    with pytest.raises(EgressUnavailable, match="Refusing"):
        VMwareFusionTarget(
            vmrun="/bin/true", vmx=Path("/tmp/x.vmx"), snapshot="clean",
            guest_user="u", guest_password="p", guest_workdir="C:\\Users\\Public",
            arch=Arch.ARM64, supports_egress=False, egress=True,
        )


def test_detonate_job_reverts_in_a_finally() -> None:
    """A failed run must not leave a dirty snapshot for the next sample."""
    from necropsy.jobs.tasks import detonate

    source = inspect.getsource(detonate.run)
    tree = ast.parse(source.lstrip())

    reverts_in_finally = False
    for node in ast.walk(tree):
        if isinstance(node, ast.Try) and node.finalbody:
            body = ast.dump(ast.Module(body=node.finalbody, type_ignores=[]))
            if "revert" in body:
                reverts_in_finally = True
    assert reverts_in_finally, "target.revert() must be called from a finally block"


def test_revert_never_raises() -> None:
    """revert() is called during teardown and must not mask the real error."""

    class ExplodingTarget(VMwareFusionTarget):
        def _run(self, command, **kwargs):  # type: ignore[no-untyped-def]
            raise OSError("vmrun is on fire")

    target = ExplodingTarget(
        vmrun="/nonexistent", vmx=Path("/tmp/x.vmx"), snapshot="clean",
        guest_user="u", guest_password="p", guest_workdir="C:\\Users\\Public",
        arch=Arch.ARM64,
    )
    target.revert()  # must not raise


def test_guest_password_is_never_rendered_into_logs() -> None:
    argv = ["vmrun", "-T", "fusion", "-gu", "analyst", "-gp", "sup3rs3cret", "start", "x.vmx"]
    rendered = _redact(argv)
    assert "sup3rs3cret" not in rendered
    assert "analyst" in rendered  # the username is not the secret


def test_every_target_implements_the_whole_contract() -> None:
    for path in REGISTRY.values():
        module_path, _, class_name = path.partition(":")
        import importlib

        cls = getattr(importlib.import_module(module_path), class_name)
        assert issubclass(cls, DetonationTarget)
        assert not getattr(cls, "__abstractmethods__", None), (
            f"{class_name} leaves abstract methods unimplemented"
        )


def test_remote_target_fails_loudly_rather_than_falling_back() -> None:
    """Silently substituting an ARM guest for a requested x86 host would
    invert the meaning of a dormant run."""
    from necropsy.sandbox.targets.remote import RemoteAgentTarget

    with pytest.raises(NoTargetConfigured, match="ARM-only"):
        RemoteAgentTarget.from_settings(object())


@pytest.mark.parametrize(
    ("target_arch", "sample_arch", "native", "expected"),
    [
        (Arch.ARM64, Arch.ARM64, True, EmulationFidelity.NATIVE),
        (Arch.ARM64, Arch.X86, True, EmulationFidelity.EMULATED),
        (Arch.ARM64, Arch.X86_64, True, EmulationFidelity.EMULATED),
        (Arch.ARM64, Arch.NOT_APPLICABLE, False, EmulationFidelity.INTERPRETED),
        (Arch.X86_64, Arch.X86_64, True, EmulationFidelity.NATIVE),
    ],
)
def test_fidelity_grading(target_arch, sample_arch, native, expected) -> None:  # type: ignore[no-untyped-def]
    caps = TargetCapabilities(
        name="t", arch=target_arch, os="windows", has_sysmon=True,
        supports_egress=False, snapshot="s", guest_workdir="w",
    )
    assert caps.fidelity_for(sample_arch, native) is expected
