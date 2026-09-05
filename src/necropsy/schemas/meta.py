from __future__ import annotations

from pydantic import BaseModel, Field


class PanelDescriptor(BaseModel):
    id: str
    title: str
    icon: str = Field(description="SF Symbols name, for the macOS shell's navigation")
    path: str = Field(description="Primary endpoint, relative to the module's mount prefix")
    stream: str | None = None
    description: str
    enabled: bool
    # Why a panel is unusable on this install. Shown to the operator rather
    # than letting a panel look available and fail on click.
    disabled_reason: str | None = None


class ModuleDescriptorOut(BaseModel):
    slug: str
    title: str
    version: str
    migration_head: str
    risk_bands: list[str]
    panels: list[PanelDescriptor]
