"""The ATT&CK taxonomy, bundled offline.

Generated from MITRE's enterprise-attack STIX release; see docs/PHASE4.md for
the regeneration step and the attribution requirement.

Two things here are not just data plumbing:

* **Tactic aliasing.** ATT&CK v19 renamed TA0005 from "Defense Evasion" to
  "Stealth" and added TA0112 "Defense Impairment". Every Sigma rule, blog post
  and hand-written mapping in existence still says `defense-evasion`, so the
  old name resolves to the new tactic rather than silently missing.
* **Kill chain mapping.** ATT&CK tactics do not map one-to-one onto the
  Lockheed Martin Cyber Kill Chain, and pretending otherwise produces a tidy
  diagram that misleads. The mapping here is an explicit, documented
  convenience view -- see KILL_CHAIN_NOTE.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

from necropsy.enums import KillChainPhase

DATA_FILE = Path(__file__).parent / "data" / "enterprise.json"

# Names that used to be, or are commonly written as, something else.
TACTIC_ALIASES: dict[str, str] = {
    "defense-evasion": "stealth",
    "defense_evasion": "stealth",
    "defence-evasion": "stealth",
    "defenseevasion": "stealth",
    "command-and-control": "command-and-control",
    "command_and_control": "command-and-control",
    "privilege_escalation": "privilege-escalation",
    "credential_access": "credential-access",
    "initial_access": "initial-access",
    "lateral_movement": "lateral-movement",
    "resource_development": "resource-development",
}

KILL_CHAIN_NOTE = (
    "ATT&CK tactics and the Cyber Kill Chain are different models: ATT&CK describes "
    "adversary goals observed post-compromise, the kill chain describes an intrusion's "
    "stages. This mapping is a presentation convenience so both views render from one "
    "set of findings; it is not a MITRE-published equivalence."
)

TACTIC_TO_KILL_CHAIN: dict[str, KillChainPhase] = {
    "reconnaissance": KillChainPhase.RECONNAISSANCE,
    "resource-development": KillChainPhase.WEAPONISATION,
    "initial-access": KillChainPhase.DELIVERY,
    "execution": KillChainPhase.EXPLOITATION,
    "privilege-escalation": KillChainPhase.EXPLOITATION,
    "persistence": KillChainPhase.INSTALLATION,
    "stealth": KillChainPhase.INSTALLATION,
    "defense-impairment": KillChainPhase.INSTALLATION,
    "discovery": KillChainPhase.RECONNAISSANCE,
    "credential-access": KillChainPhase.ACTIONS_ON_OBJECTIVES,
    "lateral-movement": KillChainPhase.ACTIONS_ON_OBJECTIVES,
    "collection": KillChainPhase.ACTIONS_ON_OBJECTIVES,
    "command-and-control": KillChainPhase.COMMAND_AND_CONTROL,
    "exfiltration": KillChainPhase.ACTIONS_ON_OBJECTIVES,
    "impact": KillChainPhase.ACTIONS_ON_OBJECTIVES,
}


@dataclass(frozen=True)
class Technique:
    id: str
    name: str
    tactics: tuple[str, ...]
    is_subtechnique: bool
    parent: str | None
    platforms: tuple[str, ...]
    log_sources: tuple[str, ...]
    sysmon_event_codes: tuple[str, ...]

    @property
    def url(self) -> str:
        return f"https://attack.mitre.org/techniques/{self.id.replace('.', '/')}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id, "name": self.name, "tactics": list(self.tactics),
            "is_subtechnique": self.is_subtechnique, "parent": self.parent,
            "platforms": list(self.platforms), "log_sources": list(self.log_sources),
            "sysmon_event_codes": list(self.sysmon_event_codes), "url": self.url,
        }


class Catalogue:
    def __init__(self, payload: dict[str, Any]) -> None:
        self.attack_version: str = payload.get("attack_version", "unknown")
        self.tactic_order: list[str] = payload.get("tactic_order", [])
        self._tactics: dict[str, dict[str, str]] = payload.get("tactics", {})
        # Old technique ID -> its replacement. ATT&CK v19 revoked the whole
        # T1562 "Impair Defenses" family in favour of the new Defense
        # Impairment tactic, and the public Sigma corpus is still full of the
        # old IDs. Following revocations keeps those rules on the matrix
        # instead of rendering every one of them as unknown.
        self._revoked: dict[str, str] = payload.get("revoked", {})
        self._techniques: dict[str, Technique] = {
            tid: Technique(
                id=tid,
                name=t["name"],
                tactics=tuple(t.get("tactics", ())),
                is_subtechnique=bool(t.get("sub")),
                parent=t.get("parent"),
                platforms=tuple(t.get("platforms", ())),
                log_sources=tuple(t.get("log_sources", ())),
                sysmon_event_codes=tuple(t.get("sysmon_event_codes", ())),
            )
            for tid, t in payload.get("techniques", {}).items()
        }

    # -- lookup -------------------------------------------------------------

    def get(self, technique_id: str) -> Technique | None:
        return self._techniques.get(technique_id.strip().upper())

    def __contains__(self, technique_id: str) -> bool:
        return self.get(technique_id) is not None

    def __len__(self) -> int:
        return len(self._techniques)

    def resolve(self, technique_id: str) -> Technique:
        """Look up a technique, falling back to its parent, then to a stub.

        An unknown ID must never lose a finding from the heatmap: a stale or
        mistyped technique still represents real evidence, and dropping it
        would quietly shrink the picture.
        """
        found = self.get(technique_id)
        if found is not None:
            return found

        cleaned = technique_id.strip().upper()

        replacement = self.replacement_for(cleaned)
        if replacement is not None:
            return replacement

        if "." in cleaned:
            parent = self.get(cleaned.split(".")[0])
            if parent is not None:
                return parent
        return Technique(
            id=cleaned, name=f"{cleaned} (not in ATT&CK {self.attack_version})",
            tactics=(), is_subtechnique="." in cleaned,
            parent=cleaned.split(".")[0] if "." in cleaned else None,
            platforms=(), log_sources=(), sysmon_event_codes=(),
        )

    def replacement_for(self, technique_id: str, _depth: int = 0) -> Technique | None:
        """Follow a revocation chain to the technique that superseded this one."""
        if _depth > 4:
            return None
        target = self._revoked.get(technique_id.strip().upper())
        if target is None:
            return None
        found = self.get(target)
        return found if found is not None else self.replacement_for(target, _depth + 1)

    def is_revoked(self, technique_id: str) -> bool:
        return technique_id.strip().upper() in self._revoked

    def base_technique(self, technique_id: str) -> str:
        return technique_id.strip().upper().split(".")[0]

    def subtechniques_of(self, technique_id: str) -> list[Technique]:
        base = self.base_technique(technique_id)
        return sorted(
            (t for t in self._techniques.values() if t.parent == base), key=lambda t: t.id
        )

    # -- tactics ------------------------------------------------------------

    def normalise_tactic(self, name: str) -> str:
        key = name.strip().lower().replace(" ", "-")
        return TACTIC_ALIASES.get(key, key)

    def tactic_name(self, shortname: str) -> str:
        entry = self._tactics.get(self.normalise_tactic(shortname))
        return entry["name"] if entry else shortname

    def tactic_id(self, shortname: str) -> str | None:
        entry = self._tactics.get(self.normalise_tactic(shortname))
        return entry.get("id") if entry else None

    def tactics(self) -> list[dict[str, str]]:
        return [
            {"shortname": s, "id": self._tactics[s]["id"], "name": self._tactics[s]["name"]}
            for s in self.tactic_order
            if s in self._tactics
        ]

    def kill_chain_phase(self, tactic: str) -> KillChainPhase | None:
        return TACTIC_TO_KILL_CHAIN.get(self.normalise_tactic(tactic))

    def kill_chain_for_technique(self, technique_id: str) -> KillChainPhase | None:
        """A technique's earliest kill chain phase, by matrix order.

        Techniques commonly sit in several tactics (process injection is both
        stealth and privilege escalation). Picking the earliest keeps a sample
        from appearing to skip stages it did in fact pass through.
        """
        technique = self.resolve(technique_id)
        phases = [
            (self.tactic_order.index(t) if t in self.tactic_order else 99,
             self.kill_chain_phase(t))
            for t in technique.tactics
        ]
        ranked = sorted((rank, phase) for rank, phase in phases if phase is not None)
        return ranked[0][1] if ranked else None


@lru_cache(maxsize=1)
def get_catalogue() -> Catalogue:
    return Catalogue(json.loads(DATA_FILE.read_text()))
