from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class SandboxStatus(BaseModel):
    enabled: bool
    ready: bool
    reason: str | None
    target: str | None
    known_targets: list[str]
    capabilities: dict[str, Any] | None
    pcap_interface: str | None
    elastic_ready: bool
    elastic_note: str
    run_seconds: int


class DetonationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    case_id: str
    sample_id: str
    job_id: str | None
    target: str
    target_arch: str
    target_os: str
    snapshot: str
    egress: bool
    # native / interpreted / emulated / unsupported. An emulated run's silence
    # is not evidence -- see verdict_note.
    fidelity: str
    fingerprint: dict[str, Any] = Field(default_factory=dict)
    guest_path: str | None
    guest_hostname: str | None
    exec_detail: str | None
    started_at: datetime
    finished_at: datetime | None
    run_seconds: int
    telemetry_events: int
    telemetry_source: str | None
    telemetry_note: str | None
    network_summary: dict[str, Any] = Field(default_factory=dict)
    behaviour_summary: dict[str, Any] = Field(default_factory=dict)
    readable: bool
    verdict_note: str | None
    state: str
    error: str | None
    reverted: bool
