"""Configuration. Env-prefixed NECROPSY_, .env supported."""

from __future__ import annotations

import base64
import os
from functools import lru_cache
from pathlib import Path

from typing import Annotated

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="NECROPSY_", env_file=".env", extra="ignore"
    )

    operator: str = "local"
    db_url: str = "sqlite:///./necropsy.db"
    vault_root: Path = Path("~/.necropsy/vault")
    vault_key: str | None = None
    redis_url: str = "redis://localhost:6379/1"

    # "rq" runs analysis on a worker (the real topology). "inline" runs it in
    # the calling process, which is what tests use and what makes a laptop
    # without Redis usable for a quick triage.
    job_runner: str = "rq"
    http_port: int = 8010

    # Architectures our detonation targets can actually run. The POC is ARM-only
    # (docs/ARCHITECTURE.md S5); this is what drives the arch_mismatch_risk finding.
    # NoDecode: take the raw env string and split it below, rather than letting
    # pydantic-settings insist on JSON for a comma-separated list.
    target_arches: Annotated[list[str], NoDecode] = Field(default_factory=lambda: ["arm64"])

    # Extra YARA rule files or directories, beyond the packaged set.
    yara_rule_paths: Annotated[list[str], NoDecode] = Field(default_factory=list)

    # Ghidra installation root. Blank means the decompile job reports itself
    # unavailable rather than failing.
    ghidra_home: Path | None = None
    ghidra_timeout_s: int = 1800
    ghidra_max_functions: int = 4000

    # rizin binary for fast pre-triage. Resolved on PATH when unset.
    rizin_path: str | None = None
    rizin_timeout_s: int = 120

    # -- Phase 3: dynamic analysis ------------------------------------------
    # Off by default. Detonation is the one irreversible-ish thing this
    # platform does, so it takes an explicit opt-in rather than working the
    # moment a VM path happens to be set.
    sandbox_enabled: bool = False
    sandbox_target: str = "vmware"
    vmrun_path: str | None = None
    sandbox_vmx_path: Path | None = None
    sandbox_snapshot_isolated: str | None = None
    # Egress runs need their own snapshot whose VM is attached to a network
    # that actually has egress. Without one, an egress request is refused
    # rather than quietly downgraded -- see targets/vmware.py.
    sandbox_snapshot_egress: str | None = None
    sandbox_guest_user: str | None = None
    sandbox_guest_password: str | None = None
    sandbox_guest_workdir: str = "C:\\Users\\Public"
    sandbox_guest_os: str = "windows"
    sandbox_guest_arch: str = "arm64"
    sandbox_guest_hostname: str | None = None
    sandbox_boot_timeout_s: int = 240
    sandbox_run_seconds: int = 120
    # Host interface to capture on. A host-only vmnet, never the uplink.
    sandbox_pcap_interface: str | None = None
    tcpdump_path: str | None = None

    # Elastic: the lab's existing cluster. Phase 3 reads guest telemetry back
    # out of it; Phase 4 adds the findings mirror.
    elastic_verify_certs: bool = True
    elastic_sysmon_index: str = "logs-windows.sysmon_operational-*"
    elastic_query_timeout_s: int = 30
    # Telemetry lands via the Elastic Agent, which is not instantaneous.
    elastic_settle_seconds: int = 20

    # Phase 4. Blank means the finding sink stays a no-op.
    elastic_url: str | None = None
    elastic_api_key: str | None = None

    # Cap on a single submitted sample. Large enough for real installers, small
    # enough that a mis-drag of a disk image fails fast.
    max_sample_bytes: int = 512 * 1024 * 1024

    @field_validator("vault_root")
    @classmethod
    def _expand(cls, v: Path) -> Path:
        return Path(os.path.expandvars(str(v))).expanduser()

    @field_validator("target_arches", "yara_rule_paths", mode="before")
    @classmethod
    def _split(cls, v: object) -> object:
        if isinstance(v, str):
            return [p.strip() for p in v.split(",") if p.strip()]
        return v

    @field_validator("ghidra_home", "sandbox_vmx_path", mode="before")
    @classmethod
    def _expand_opt(cls, v: object) -> object:
        if isinstance(v, str) and v.strip():
            return Path(os.path.expandvars(v)).expanduser()
        return v or None

    def vault_key_bytes(self) -> bytes:
        """32-byte AES key: from env, else generated once beside the vault.

        The key exists to stop XProtect eating samples and to prevent an
        accidental double-click, not to defend against a determined local
        attacker -- see docs/SAFETY.md.
        """
        if self.vault_key:
            key = base64.b64decode(self.vault_key)
            if len(key) != 32:
                raise ValueError("NECROPSY_VAULT_KEY must decode to exactly 32 bytes")
            return key

        key_path = self.vault_root.parent / "vault.key"
        if key_path.exists():
            return base64.b64decode(key_path.read_bytes())

        key = os.urandom(32)
        key_path.parent.mkdir(parents=True, exist_ok=True)
        # Write then tighten, so the key is never briefly world-readable.
        fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(fd, base64.b64encode(key))
        finally:
            os.close(fd)
        key_path.chmod(0o400)
        return key


@lru_cache
def get_settings() -> Settings:
    return Settings()
