from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from necropsy.enums import Arch, FileType, SampleSource, StorageState


class SampleOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    sha256: str
    sha1: str
    md5: str
    tlsh: str | None
    ssdeep: str | None
    size: int
    mime: str | None
    magic: str | None
    file_type: FileType
    arch: Arch
    entropy: float | None
    storage_state: StorageState
    identity: dict[str, Any] = Field(default_factory=dict)
    first_seen_at: datetime


class CaseSampleOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    case_id: str
    observed_filename: str | None
    source: SampleSource
    submitted_by: str
    note: str | None
    added_at: datetime
    sample: SampleOut


class SampleDetail(SampleOut):
    other_cases: list[dict[str, str]] = Field(default_factory=list)


class IngestByPath(BaseModel):
    """Ingest a file already on the analyst's machine, rather than uploading it."""

    path: str
    observed_filename: str | None = None
    note: str | None = None
    source: SampleSource = SampleSource.PATH


class IngestResponse(BaseModel):
    sample: SampleOut
    new_to_platform: bool
    attached_to_case: bool
    also_in_case_count: int
    identify_job_id: str | None
