"""Claude API client.

Thin on purpose: model choice, the disclosure gate, cost accounting, and error
handling that distinguishes retryable from terminal. Everything about *what* to
ask lives in `prompts.py`; everything about *checking the answer* lives in the
task modules.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, TypeVar

from pydantic import BaseModel

from necropsy.config import get_settings

log = logging.getLogger(__name__)

T = TypeVar("T", bound=BaseModel)

# Per the model table: Opus 5 is the default. Not downgraded for cost -- that is
# the operator's decision, exposed as NECROPSY_AI_MODEL.
DEFAULT_MODEL = "claude-opus-5"

# Rough Opus 5 rates, used only to show an operator what a job cost. Not billing.
USD_PER_MTOK_INPUT = 5.0
USD_PER_MTOK_OUTPUT = 25.0

try:
    import anthropic

    _HAVE_SDK = True
except ImportError:  # pragma: no cover - exercised by the degraded-path test
    _HAVE_SDK = False


# The SDK resolves credentials in this order and only fails at request time, so
# constructing a client proves nothing about whether a call will work. Probing
# the same sources up front is what lets a proposal say "no credentials" instead
# of offering work that dies with a 401.
WIF_ENV = (
    "ANTHROPIC_FEDERATION_RULE_ID",
    "ANTHROPIC_ORGANIZATION_ID",
    "ANTHROPIC_SERVICE_ACCOUNT_ID",
)


def credential_source() -> str | None:
    """Best-effort: which credential the SDK would use, or None if it has none."""
    import os
    from pathlib import Path

    if get_settings().anthropic_api_key:
        return "NECROPSY_ANTHROPIC_API_KEY"
    if os.environ.get("ANTHROPIC_API_KEY"):
        return "ANTHROPIC_API_KEY"
    if os.environ.get("ANTHROPIC_AUTH_TOKEN"):
        return "ANTHROPIC_AUTH_TOKEN"
    if all(os.environ.get(k) for k in WIF_ENV) and (
        os.environ.get("ANTHROPIC_IDENTITY_TOKEN_FILE")
        or os.environ.get("ANTHROPIC_IDENTITY_TOKEN")
    ):
        return "workload identity federation"

    profile_dir = Path(
        os.environ.get("ANTHROPIC_CONFIG_DIR", "~/.config/anthropic")
    ).expanduser()
    if profile_dir.is_dir() and any(profile_dir.iterdir()):
        return f"ant profile ({profile_dir})"
    return None


class AIError(RuntimeError):
    pass


class AIUnavailable(AIError):
    """No SDK, or no credentials."""


class AIDisclosureDenied(AIError):
    """The case forbids sending sample-derived content to a third party."""


@dataclass
class Usage:
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    calls: int = 0

    def add(self, usage: Any) -> None:
        self.calls += 1
        self.input_tokens += getattr(usage, "input_tokens", 0) or 0
        self.output_tokens += getattr(usage, "output_tokens", 0) or 0
        self.cache_read_tokens += getattr(usage, "cache_read_input_tokens", 0) or 0

    @property
    def estimated_usd(self) -> float:
        return round(
            self.input_tokens / 1e6 * USD_PER_MTOK_INPUT
            + self.output_tokens / 1e6 * USD_PER_MTOK_OUTPUT,
            4,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "calls": self.calls,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "cache_read_tokens": self.cache_read_tokens,
            "estimated_usd": self.estimated_usd,
        }


@dataclass
class AIClient:
    """Wraps the Anthropic SDK for Necropsy's three AI tasks."""

    model: str = DEFAULT_MODEL
    effort: str = "high"
    max_tokens: int = 16000
    _client: Any = None
    usage: Usage = field(default_factory=Usage)

    @classmethod
    def from_settings(cls) -> AIClient:
        if not _HAVE_SDK:
            raise AIUnavailable(
                "the anthropic SDK is not installed; pip install necropsy[ai]"
            )
        settings = get_settings()
        if credential_source() is None:
            raise AIUnavailable(
                "no Anthropic credentials found; set ANTHROPIC_API_KEY or run "
                "`ant auth login`"
            )
        try:
            # Zero-arg construction resolves ANTHROPIC_API_KEY, ANTHROPIC_AUTH_TOKEN
            # or an `ant auth login` profile. An explicit key overrides.
            client = (
                anthropic.Anthropic(api_key=settings.anthropic_api_key)
                if settings.anthropic_api_key
                else anthropic.Anthropic()
            )
        except Exception as exc:  # noqa: BLE001
            raise AIUnavailable(f"could not construct an Anthropic client: {exc}") from exc

        return cls(
            model=settings.ai_model or DEFAULT_MODEL,
            effort=settings.ai_effort,
            max_tokens=settings.ai_max_tokens,
            _client=client,
        )

    @classmethod
    def try_from_settings(cls) -> AIClient | None:
        try:
            return cls.from_settings()
        except AIUnavailable:
            return None

    # -- the disclosure gate ------------------------------------------------

    @staticmethod
    def require_disclosure(case: Any) -> None:
        """Refuse to send anything derived from a case that forbids it.

        The same check runs in actions/service.py at the point of decision.
        This one exists because that is a policy gate on a user action, and
        this is the last line before bytes leave the machine -- a future code
        path that skips the first must still hit this.
        """
        if case is None or not getattr(case, "ai_disclosure_allowed", False):
            raise AIDisclosureDenied(
                "this case has ai_disclosure_allowed set to false; sample-derived "
                "content may not be sent to a third-party API"
            )

    # -- calling ------------------------------------------------------------

    def parse(
        self,
        *,
        system: str,
        user: str,
        schema: type[T],
        max_tokens: int | None = None,
    ) -> T:
        """One structured-output call. Returns the validated model."""
        if self._client is None:
            raise AIUnavailable("no Anthropic client configured")

        try:
            response = self._client.messages.parse(
                model=self.model,
                max_tokens=max_tokens or self.max_tokens,
                system=system,
                thinking={"type": "adaptive"},
                output_config={"effort": self.effort},
                output_format=schema,
                messages=[{"role": "user", "content": user}],
            )
        except Exception as exc:  # noqa: BLE001 - narrowed below
            raise self._translate(exc) from exc

        self.usage.add(getattr(response, "usage", None))

        if getattr(response, "stop_reason", None) == "refusal":
            details = getattr(response, "stop_details", None)
            raise AIError(
                "the model declined this request"
                + (f" ({getattr(details, 'category', '?')})" if details else "")
            )

        parsed = getattr(response, "parsed_output", None)
        if parsed is None:
            raise AIError("the model returned no parseable structured output")
        return parsed  # type: ignore[return-value]

    def count_tokens(self, *, system: str, user: str) -> int:
        """Estimate input size before committing to a call."""
        if self._client is None:
            return 0
        try:
            result = self._client.messages.count_tokens(
                model=self.model,
                system=system,
                messages=[{"role": "user", "content": user}],
            )
            return int(getattr(result, "input_tokens", 0))
        except Exception:  # noqa: BLE001 - an estimate must never fail a job
            return 0

    def _translate(self, exc: Exception) -> AIError:
        if not _HAVE_SDK:
            return AIError(str(exc))
        if isinstance(exc, anthropic.AuthenticationError):
            return AIUnavailable(
                "Anthropic rejected the credentials; set ANTHROPIC_API_KEY or run `ant auth login`"
            )
        if isinstance(exc, anthropic.PermissionDeniedError):
            return AIUnavailable("the credential lacks permission for this model")
        if isinstance(exc, anthropic.NotFoundError):
            return AIError(f"unknown model {self.model!r}")
        if isinstance(exc, anthropic.RateLimitError):
            return AIError("rate limited by the Anthropic API; retry later")
        if isinstance(exc, anthropic.APIConnectionError):
            return AIUnavailable(f"could not reach the Anthropic API: {exc}")
        if isinstance(exc, anthropic.APIStatusError):
            return AIError(f"Anthropic API error {exc.status_code}: {exc.message}")
        return AIError(f"{type(exc).__name__}: {exc}")


def have_sdk() -> bool:
    return _HAVE_SDK


def have_credentials() -> bool:
    return credential_source() is not None
