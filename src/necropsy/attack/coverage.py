"""Per-case ATT&CK rollup: the heatmap, and what the lab could not have seen.

Three judgements are baked in, and each exists because the naive version
misleads:

* **Observed beats inferred.** A technique seen in a detonation is a stronger
  claim than one inferred from an import table. A heatmap that renders both as
  one colour flattens the most important distinction in the case.
* **Emulated evidence carries its caveat.** If a technique's only dynamic
  evidence came from a run under architecture emulation, the cell says so.
* **Absence is reported as gap, not as clean.** For every technique in the
  case, MITRE names the log sources that detect it; comparing that with what
  the lab actually collects turns "we saw nothing" into "we could not have
  seen this", which is the difference between reassurance and a work item.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy.orm import Session

from necropsy.attack.catalogue import KILL_CHAIN_NOTE, Catalogue, Technique, get_catalogue
from necropsy.db.models import Finding
from necropsy.db.repos import findings as findings_repo
from necropsy.elastic.sysmon import INTERESTING_EVENTS
from necropsy.enums import Producer, Severity

SEVERITY_RANK = {
    Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 2,
    Severity.HIGH: 3, Severity.CRITICAL: 4,
}
RANK_TO_SEVERITY = {v: k for k, v in SEVERITY_RANK.items()}

# Producers whose findings describe something the sample actually did.
OBSERVED_PRODUCERS = {Producer.SANDBOX, Producer.SYSMON, Producer.ZEEK}

# Fidelity values that make a dynamic observation unreliable.
WEAK_FIDELITY = {"emulated", "unsupported"}


@dataclass
class TechniqueCell:
    technique: Technique
    finding_count: int = 0
    max_severity: Severity = Severity.INFO
    max_confidence: float = 0.0
    producers: set[str] = field(default_factory=set)
    subtechniques: set[str] = field(default_factory=set)
    observed: bool = False
    inferred: bool = False
    weak_fidelity: bool = False
    finding_ids: list[str] = field(default_factory=list)

    @property
    def evidence_grade(self) -> str:
        if self.observed and not self.weak_fidelity:
            return "observed"
        if self.observed:
            return "observed_emulated"
        return "inferred"

    @property
    def caveat(self) -> str | None:
        if self.evidence_grade == "observed_emulated":
            return (
                "Observed only in a run under architecture emulation. The behaviour was "
                "recorded, but the run's negative space proves nothing."
            )
        if self.evidence_grade == "inferred":
            return (
                "Inferred from static analysis: the sample is equipped to do this. Not "
                "evidence that it did."
            )
        return None

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.technique.to_dict(),
            "finding_count": self.finding_count,
            "max_severity": self.max_severity.value,
            "max_confidence": round(self.max_confidence, 2),
            "producers": sorted(self.producers),
            "subtechniques": sorted(self.subtechniques),
            "evidence_grade": self.evidence_grade,
            "caveat": self.caveat,
            "finding_ids": self.finding_ids[:50],
        }


@dataclass
class TacticColumn:
    shortname: str
    id: str | None
    name: str
    cells: list[TechniqueCell] = field(default_factory=list)

    @property
    def max_severity(self) -> Severity:
        return max((c.max_severity for c in self.cells), key=lambda s: SEVERITY_RANK[s],
                   default=Severity.INFO)

    def to_dict(self) -> dict[str, Any]:
        return {
            "shortname": self.shortname, "id": self.id, "name": self.name,
            "technique_count": len(self.cells),
            "max_severity": self.max_severity.value,
            "techniques": [c.to_dict() for c in self.cells],
        }


@dataclass
class DetectionGap:
    technique_id: str
    technique_name: str
    required_sysmon_codes: list[str]
    missing_sysmon_codes: list[str]
    log_sources: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "technique_id": self.technique_id, "technique_name": self.technique_name,
            "required_sysmon_codes": self.required_sysmon_codes,
            "missing_sysmon_codes": self.missing_sysmon_codes,
            "log_sources": self.log_sources,
        }


@dataclass
class CaseCoverage:
    case_id: str
    attack_version: str
    tactics: list[TacticColumn] = field(default_factory=list)
    kill_chain: dict[str, list[str]] = field(default_factory=dict)
    technique_count: int = 0
    observed_count: int = 0
    inferred_count: int = 0
    unmapped_finding_count: int = 0
    detection_gaps: list[DetectionGap] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "attack_version": self.attack_version,
            "technique_count": self.technique_count,
            "observed_count": self.observed_count,
            "inferred_count": self.inferred_count,
            "unmapped_finding_count": self.unmapped_finding_count,
            "tactics": [t.to_dict() for t in self.tactics],
            "kill_chain": self.kill_chain,
            "kill_chain_note": KILL_CHAIN_NOTE,
            "detection_gaps": [g.to_dict() for g in self.detection_gaps],
            "notes": self.notes,
        }


def build(
    session: Session,
    case_id: str,
    *,
    collected_sysmon_codes: list[str] | None = None,
) -> CaseCoverage:
    catalogue = get_catalogue()
    findings = findings_repo.for_case(session, case_id, limit=5000)
    return build_from_findings(
        case_id, findings, catalogue=catalogue,
        collected_sysmon_codes=collected_sysmon_codes,
    )


def build_from_findings(
    case_id: str,
    findings: list[Finding],
    *,
    catalogue: Catalogue | None = None,
    collected_sysmon_codes: list[str] | None = None,
) -> CaseCoverage:
    catalogue = catalogue or get_catalogue()
    collected = set(collected_sysmon_codes or INTERESTING_EVENTS)

    coverage = CaseCoverage(case_id=case_id, attack_version=catalogue.attack_version)
    cells: dict[str, TechniqueCell] = {}

    for finding in findings:
        technique_ids = finding.attack_technique_ids or []
        if not technique_ids:
            coverage.unmapped_finding_count += 1
            continue

        weak = str((finding.evidence or {}).get("fidelity", "")).lower() in WEAK_FIDELITY
        observed = finding.producer in OBSERVED_PRODUCERS

        for raw_id in technique_ids:
            technique = catalogue.resolve(raw_id)
            # Sub-techniques roll into their parent so the matrix stays readable;
            # the specific IDs are kept on the cell.
            base_id = technique.parent or technique.id
            base = catalogue.resolve(base_id)

            cell = cells.get(base.id)
            if cell is None:
                cell = TechniqueCell(technique=base)
                cells[base.id] = cell

            cell.finding_count += 1
            cell.finding_ids.append(finding.id)
            cell.producers.add(finding.producer.value)
            if technique.id != base.id:
                cell.subtechniques.add(technique.id)
            if SEVERITY_RANK[finding.severity] > SEVERITY_RANK[cell.max_severity]:
                cell.max_severity = finding.severity
            cell.max_confidence = max(cell.max_confidence, finding.confidence)

            if observed:
                cell.observed = True
                # A cell stops being caveated as soon as one solid run backs it.
                cell.weak_fidelity = (cell.weak_fidelity or weak) and weak
            else:
                cell.inferred = True

    # Lay cells out on the matrix, in MITRE's own tactic order.
    by_tactic: dict[str, list[TechniqueCell]] = defaultdict(list)
    for cell in cells.values():
        tactics = cell.technique.tactics or ("unmapped",)
        for tactic in tactics:
            by_tactic[catalogue.normalise_tactic(tactic)].append(cell)

    for tactic in catalogue.tactic_order:
        if tactic not in by_tactic:
            continue
        column = TacticColumn(
            shortname=tactic, id=catalogue.tactic_id(tactic), name=catalogue.tactic_name(tactic)
        )
        column.cells = sorted(
            by_tactic[tactic],
            key=lambda c: (-SEVERITY_RANK[c.max_severity], -c.max_confidence, c.technique.id),
        )
        coverage.tactics.append(column)

    if "unmapped" in by_tactic:
        column = TacticColumn(shortname="unmapped", id=None, name="Not mapped to a tactic")
        column.cells = sorted(by_tactic["unmapped"], key=lambda c: c.technique.id)
        coverage.tactics.append(column)

    coverage.technique_count = len(cells)
    coverage.observed_count = sum(1 for c in cells.values() if c.observed)
    coverage.inferred_count = sum(1 for c in cells.values() if not c.observed)

    kill_chain: dict[str, list[str]] = defaultdict(list)
    for cell in cells.values():
        phase = catalogue.kill_chain_for_technique(cell.technique.id)
        kill_chain[phase.value if phase else "unmapped"].append(cell.technique.id)
    coverage.kill_chain = {k: sorted(v) for k, v in kill_chain.items()}

    coverage.detection_gaps = _detection_gaps(cells.values(), collected)
    coverage.notes = _notes(coverage)
    return coverage


def _detection_gaps(cells: Any, collected: set[str]) -> list[DetectionGap]:
    """Techniques in this case that the lab's telemetry cannot see.

    Only meaningful for techniques we did *not* observe: if the sandbox caught
    it anyway, the gap is academic. This is the "plug the gap" output -- each
    row is a concrete Sysmon configuration change.
    """
    gaps: list[DetectionGap] = []
    for cell in cells:
        if cell.observed:
            continue
        required = set(cell.technique.sysmon_event_codes)
        if not required:
            continue
        missing = required - collected
        if missing:
            gaps.append(
                DetectionGap(
                    technique_id=cell.technique.id,
                    technique_name=cell.technique.name,
                    required_sysmon_codes=sorted(required, key=int),
                    missing_sysmon_codes=sorted(missing, key=int),
                    log_sources=list(cell.technique.log_sources),
                )
            )
    return sorted(gaps, key=lambda g: (-len(g.missing_sysmon_codes), g.technique_id))


def _notes(coverage: CaseCoverage) -> list[str]:
    notes: list[str] = []
    if coverage.technique_count and not coverage.observed_count:
        notes.append(
            "Every technique in this case is inferred from static analysis. Nothing here "
            "is evidence the sample did anything -- only that it is equipped to."
        )
    if coverage.unmapped_finding_count:
        notes.append(
            f"{coverage.unmapped_finding_count} finding(s) carry no ATT&CK technique and "
            "do not appear on the matrix. The matrix is a view of the case, not the case."
        )
    if coverage.detection_gaps:
        missing = sorted({c for g in coverage.detection_gaps for c in g.missing_sysmon_codes},
                         key=int)
        notes.append(
            f"{len(coverage.detection_gaps)} technique(s) in this case need Sysmon events "
            f"the lab does not collect ({', '.join(missing)}). Absence of behavioural "
            "evidence for those is a visibility gap, not a negative result."
        )
    return notes
