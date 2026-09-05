"""The AI layer: function summaries, case reports, drafted YARA rules.

Three constraints shape everything here, and they are not incidental:

1. **Sample-derived content is attacker-controlled.** Decompiled code and
   extracted strings come out of malware. A sample can contain text written to
   manipulate a model that reads it. Every prompt in this package treats that
   content as untrusted data inside a nonce-delimited envelope, never as
   instruction, and asks the model to *report* embedded instructions rather
   than follow them. See `prompts.py`.
2. **The disclosure gate is enforced here too.** `Case.ai_disclosure_allowed`
   is checked at the point of decision in `actions/service.py`; the client
   re-checks before every call. Defence in depth on the one action that sends
   client material off the machine.
3. **Model output is a draft, never a verdict.** Summaries are labelled and
   confidence-scored; drafted YARA rules are compiled, tested against the real
   sample and against a benign corpus, and discarded if they fail. Nothing the
   model produces reaches a case as fact without being checked.
"""

from necropsy.ai.client import (
    AIClient,
    AIDisclosureDenied,
    AIError,
    AIUnavailable,
    credential_source,
    have_credentials,
)

__all__ = [
    "AIClient",
    "AIDisclosureDenied",
    "AIError",
    "AIUnavailable",
    "credential_source",
    "have_credentials",
]
