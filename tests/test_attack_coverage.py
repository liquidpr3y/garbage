"""Per-case ATT&CK rollup: the heatmap and the detection-gap analysis."""

from __future__ import annotations

from necropsy.attack.coverage import build_from_findings
from necropsy.db.models import Finding
from necropsy.enums import KillChainPhase, Producer, Severity


def finding(
    technique_ids: list[str],
    *,
    producer: Producer = Producer.CAPABILITY,
    severity: Severity = Severity.MEDIUM,
    confidence: float = 0.6,
    fidelity: str | None = None,
    ftype: str = "x",
) -> Finding:
    return Finding(
        id=f"f-{ftype}-{'-'.join(technique_ids) or 'none'}",
        case_id="c-1", producer=producer, type=ftype, title=ftype,
        severity=severity, confidence=confidence,
        attack_technique_ids=technique_ids,
        kill_chain_phase=KillChainPhase.INSTALLATION,
        evidence={"fidelity": fidelity} if fidelity else {},
        dedupe_key=ftype,
    )


def _cell(coverage, technique_id: str):  # type: ignore[no-untyped-def]
    for tactic in coverage.tactics:
        for cell in tactic.cells:
            if cell.technique.id == technique_id:
                return cell
    raise AssertionError(f"{technique_id} not on the matrix")


def test_subtechniques_roll_into_their_parent() -> None:
    coverage = build_from_findings("c-1", [finding(["T1055.002"]), finding(["T1055.012"], ftype="y")])
    cell = _cell(coverage, "T1055")
    assert cell.subtechniques == {"T1055.002", "T1055.012"}
    assert coverage.technique_count == 1


def test_a_technique_appears_in_every_tactic_it_belongs_to() -> None:
    coverage = build_from_findings("c-1", [finding(["T1055"])])
    tactics = {t.shortname for t in coverage.tactics}
    assert {"stealth", "privilege-escalation"} <= tactics


def test_tactic_columns_follow_matrix_order() -> None:
    coverage = build_from_findings(
        "c-1", [finding(["T1490"]), finding(["T1547.001"], ftype="p"), finding(["T1592"], ftype="r")]
    )
    order = [t.shortname for t in coverage.tactics]
    assert order.index("reconnaissance") < order.index("persistence") < order.index("impact")


def test_observed_outranks_inferred() -> None:
    """The distinction the heatmap exists to show."""
    inferred = build_from_findings("c-1", [finding(["T1547.001"], producer=Producer.CAPABILITY)])
    assert _cell(inferred, "T1547").evidence_grade == "inferred"
    assert "Not evidence that it did" in _cell(inferred, "T1547").caveat

    observed = build_from_findings(
        "c-1", [finding(["T1547.001"], producer=Producer.SANDBOX, fidelity="native")]
    )
    assert _cell(observed, "T1547").evidence_grade == "observed"
    assert _cell(observed, "T1547").caveat is None


def test_emulated_observation_keeps_its_caveat() -> None:
    coverage = build_from_findings(
        "c-1", [finding(["T1547.001"], producer=Producer.SANDBOX, fidelity="emulated")]
    )
    cell = _cell(coverage, "T1547")
    assert cell.evidence_grade == "observed_emulated"
    assert "emulation" in cell.caveat


def test_one_solid_run_clears_the_emulation_caveat() -> None:
    coverage = build_from_findings("c-1", [
        finding(["T1547.001"], producer=Producer.SANDBOX, fidelity="emulated", ftype="a"),
        finding(["T1547.001"], producer=Producer.SANDBOX, fidelity="native", ftype="b"),
    ])
    assert _cell(coverage, "T1547").evidence_grade == "observed"


def test_severity_and_producers_aggregate() -> None:
    coverage = build_from_findings("c-1", [
        finding(["T1055"], severity=Severity.LOW, producer=Producer.CAPABILITY, ftype="a"),
        finding(["T1055"], severity=Severity.CRITICAL, producer=Producer.SANDBOX, ftype="b"),
    ])
    cell = _cell(coverage, "T1055")
    assert cell.max_severity is Severity.CRITICAL
    assert cell.producers == {"capability", "sandbox"}
    assert cell.finding_count == 2


def test_unmapped_findings_are_counted_not_dropped() -> None:
    coverage = build_from_findings("c-1", [finding([]), finding(["T1055"], ftype="b")])
    assert coverage.unmapped_finding_count == 1
    assert any("do not appear on the matrix" in n for n in coverage.notes)


def test_revoked_ids_land_on_their_replacement() -> None:
    coverage = build_from_findings("c-1", [finding(["T1562.001"])])
    assert _cell(coverage, "T1685").technique.name == "Disable or Modify Tools"


def test_an_all_static_case_says_so() -> None:
    coverage = build_from_findings("c-1", [finding(["T1055"]), finding(["T1490"], ftype="b")])
    assert coverage.observed_count == 0
    assert any("equipped to" in n for n in coverage.notes)


def test_kill_chain_view_is_populated() -> None:
    coverage = build_from_findings("c-1", [finding(["T1547.001"]), finding(["T1490"], ftype="b")])
    assert "installation" in coverage.kill_chain
    assert "actions_on_objectives" in coverage.kill_chain


def test_detection_gaps_name_the_missing_sysmon_events() -> None:
    """The 'plug the gap' output: each row is a Sysmon configuration change."""
    coverage = build_from_findings(
        "c-1", [finding(["T1055"])], collected_sysmon_codes=["1", "3"]
    )
    gap = next(g for g in coverage.detection_gaps if g.technique_id == "T1055")
    assert "7" in gap.missing_sysmon_codes  # image load, which we are not collecting
    assert "1" not in gap.missing_sysmon_codes
    assert any("visibility gap, not a negative result" in n for n in coverage.notes)


def test_an_observed_technique_is_not_reported_as_a_gap() -> None:
    """If the sandbox caught it anyway, the missing log source is academic."""
    coverage = build_from_findings(
        "c-1",
        [finding(["T1055"], producer=Producer.SANDBOX, fidelity="native")],
        collected_sysmon_codes=["1"],
    )
    assert not [g for g in coverage.detection_gaps if g.technique_id == "T1055"]


def test_full_sysmon_collection_produces_no_gaps_for_covered_techniques() -> None:
    coverage = build_from_findings(
        "c-1", [finding(["T1547.001"])], collected_sysmon_codes=["1", "13", "14"]
    )
    assert coverage.detection_gaps == []


def test_empty_case_is_an_empty_matrix_not_an_error() -> None:
    coverage = build_from_findings("c-1", [])
    assert coverage.technique_count == 0
    assert coverage.tactics == []
    assert coverage.to_dict()["kill_chain_note"]
