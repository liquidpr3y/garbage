"""Test fixtures.

Two rules for this suite, both non-negotiable:

* No real malware, ever. Fixtures are synthesised benign binaries with valid
  headers. A repository that has ever held a sample is a repository you cannot
  make public, and test fixtures are exactly how that happens by accident.
* No network, no Redis, no lab. CI has to run on a machine that has never seen
  the VMware host.
"""

from __future__ import annotations

import base64
import os
import struct
from pathlib import Path

import pytest

from necropsy.config import Settings, get_settings
from necropsy.contracts.events import Event
from necropsy.contracts.host import RiskPolicy


@pytest.fixture
def workdir(tmp_path: Path) -> Path:
    return tmp_path


@pytest.fixture(autouse=True)
def settings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Settings:
    """Point every global at a throwaway directory, inline job execution."""
    monkeypatch.setenv("NECROPSY_DB_URL", f"sqlite:///{tmp_path / 'necropsy.db'}")
    monkeypatch.setenv("NECROPSY_VAULT_ROOT", str(tmp_path / "vault"))
    monkeypatch.setenv("NECROPSY_VAULT_KEY", base64.b64encode(os.urandom(32)).decode())
    monkeypatch.setenv("NECROPSY_OPERATOR", "test.analyst")
    monkeypatch.setenv("NECROPSY_JOB_RUNNER", "inline")
    monkeypatch.setenv("NECROPSY_TARGET_ARCHES", "arm64")
    get_settings.cache_clear()
    yield get_settings()
    get_settings.cache_clear()


@pytest.fixture(autouse=True)
def database(settings: Settings):  # type: ignore[no-untyped-def]
    from necropsy.db.session import configure, create_all, make_engine

    engine = make_engine(settings.db_url)
    configure(engine)
    create_all(engine)
    yield engine
    engine.dispose()


class FakeHost:
    """HostServices with no broker. Records published events for assertions."""

    def __init__(self, actor: str = "test.analyst") -> None:
        self.events: list[tuple[str, Event]] = []
        self._actor = actor

    def redis(self):  # type: ignore[no-untyped-def]
        raise RuntimeError("no broker in tests")

    def publish(self, channel: str, event: Event) -> None:
        self.events.append((channel, event))

    def actor(self) -> str:
        return self._actor

    def artifact_root(self) -> Path:
        return get_settings().vault_root

    def risk_policy(self) -> RiskPolicy:
        return RiskPolicy()

    def resolve_engagement(self, ref: str):  # type: ignore[no-untyped-def]
        return None

    def has(self, capability: str) -> bool:
        return False

    def types(self, event_type) -> list[Event]:  # type: ignore[no-untyped-def]
        return [e for _, e in self.events if e.type == event_type]


@pytest.fixture(autouse=True)
def host() -> FakeHost:
    from necropsy.runtime import reset_host, set_host

    fake = FakeHost()
    set_host(fake)
    yield fake
    reset_host()


@pytest.fixture(autouse=True)
def inline_runner():  # type: ignore[no-untyped-def]
    from necropsy.jobs.runner import InlineRunner, set_runner

    set_runner(InlineRunner())
    yield
    set_runner(None)  # type: ignore[arg-type]
    import necropsy.jobs.runner as runner_mod

    runner_mod._runner = None


@pytest.fixture
def session():  # type: ignore[no-untyped-def]
    from necropsy.db.session import get_sessionmaker

    s = get_sessionmaker()()
    try:
        yield s
    finally:
        s.close()


# -- synthetic samples -------------------------------------------------------


def make_pe(
    path: Path,
    *,
    machine: int = 0x8664,
    signed: bool = False,
    high_entropy: bool = False,
    size: int = 8192,
) -> Path:
    """A structurally valid PE header on inert filler.

    Enough of a PE for our parser to answer the two questions Phase 1 asks --
    architecture and signature presence -- and nothing that executes.
    """
    e_lfanew = 0x80
    buf = bytearray(b"\x00" * size)
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, e_lfanew)
    buf[e_lfanew : e_lfanew + 4] = b"PE\x00\x00"

    coff = e_lfanew + 4
    size_opt = 240
    struct.pack_into("<HHIIIHH", buf, coff, machine, 1, 0x60000000, 0, 0, size_opt, 0x0022)

    opt = coff + 20
    struct.pack_into("<H", buf, opt, 0x20B)  # PE32+
    struct.pack_into("<H", buf, opt + 68, 3)  # subsystem: console
    struct.pack_into("<H", buf, opt + 70, 0x8160)  # dll characteristics
    struct.pack_into("<I", buf, opt + 108, 16)  # NumberOfRvaAndSizes
    dirs = opt + 112
    if signed:
        struct.pack_into("<II", buf, dirs + 32, 0x7000, 0x1800)

    sections = opt + size_opt
    buf[sections : sections + 8] = b".text\x00\x00\x00"

    filler_at = sections + 40
    if high_entropy:
        buf[filler_at:] = os.urandom(size - filler_at)
    else:
        buf[filler_at:] = (b"A" * 64 + b"\x00" * 64) * ((size - filler_at) // 128 + 1)

    data = bytes(buf[:size])
    path.write_bytes(data)
    return path


def make_ooxml_with_macro(path: Path) -> Path:
    import zipfile

    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("[Content_Types].xml", "<Types/>")
        zf.writestr("word/document.xml", "<document/>")
        zf.writestr("word/vbaProject.bin", b"\x00" * 512)
    return path


@pytest.fixture
def pe_sample(tmp_path: Path) -> Path:
    return make_pe(tmp_path / "invoice.exe")


# -- richer Phase 2 fixtures, built with a real import table ------------------


def loader_spec() -> "PESpec":
    """A shape that trips several capability detectors at once.

    Inert: the entry point is a `ret` and no imported function is ever called.
    """
    from pebuilder import PESpec

    return PESpec(
        imports={
            "kernel32.dll": [
                "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
                "OpenProcess", "LoadLibraryA", "GetProcAddress",
            ],
            "advapi32.dll": ["RegSetValueExA", "OpenSCManagerA", "CreateServiceA"],
            "wininet.dll": ["InternetOpenA", "InternetConnectA", "HttpSendRequestA"],
        },
        add_wx_section=True,
        tls_callbacks=2,
        pdb_path=r"C:\dev\loader\x64\Release\loader.pdb",
        extra_rdata_strings=[
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            "http://185.220.101.44/gate.php",
            "vssadmin delete shadows",
            "Win32_ShadowCopy",
            "VBoxService",
            "vmtoolsd",
            "Mozilla/5.0 (Windows NT 10.0) Loader/2.1",
        ],
    )


@pytest.fixture
def loader_sample(tmp_path: Path) -> Path:
    from pebuilder import build

    return build(tmp_path / "loader.exe", loader_spec())


@pytest.fixture
def plain_sample(tmp_path: Path) -> Path:
    """A PE with nothing interesting in it -- the true-negative control."""
    from pebuilder import PESpec, build

    return build(
        tmp_path / "helper.exe",
        PESpec(imports={"kernel32.dll": ["GetLastError", "CloseHandle", "Sleep"]}),
    )


@pytest.fixture
def x86_packed_sample(tmp_path: Path) -> Path:
    return make_pe(tmp_path / "packed.exe", machine=0x014C, high_entropy=True)


@pytest.fixture
def macro_doc(tmp_path: Path) -> Path:
    return make_ooxml_with_macro(tmp_path / "statement.docm")
