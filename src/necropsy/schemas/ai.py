from __future__ import annotations

from pydantic import BaseModel


class AIStatus(BaseModel):
    sdk_installed: bool
    credentials: bool
    # Which source the SDK would resolve, or null. Probed rather than assumed:
    # the client constructs fine with no credentials and fails at request time.
    credential_source: str | None
    model: str
    effort: str
    max_functions: int
    goodware_dir: str | None
    # Without a real known-good corpus, drafted YARA rules are only tested
    # against synthetic controls.
    goodware_configured: bool
