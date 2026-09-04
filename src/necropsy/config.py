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

    @field_validator("target_arches", mode="before")
    @classmethod
    def _split(cls, v: object) -> object:
        if isinstance(v, str):
            return [p.strip() for p in v.split(",") if p.strip()]
        return v

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
