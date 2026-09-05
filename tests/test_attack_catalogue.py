"""The bundled ATT&CK taxonomy."""

from __future__ import annotations

from necropsy.attack.catalogue import TACTIC_TO_KILL_CHAIN, get_catalogue
from necropsy.enums import KillChainPhase


def test_catalogue_loads_a_real_attack_release() -> None:
    catalogue = get_catalogue()
    assert catalogue.attack_version != "unknown"
    assert len(catalogue) > 600
    assert len(catalogue.tactics()) >= 14


def test_tactics_are_in_matrix_order() -> None:
    order = [t["shortname"] for t in get_catalogue().tactics()]
    assert order[0] == "reconnaissance"
    assert order[-1] == "impact"
    assert order.index("initial-access") < order.index("persistence") < order.index("impact")


def test_the_v19_defense_evasion_rename_is_aliased() -> None:
    """ATT&CK v19 renamed TA0005 to Stealth. Every existing rule says defense-evasion."""
    catalogue = get_catalogue()
    assert catalogue.normalise_tactic("defense-evasion") == "stealth"
    assert catalogue.normalise_tactic("defense_evasion") == "stealth"
    assert catalogue.tactic_id("defense-evasion") == "TA0005"
    assert catalogue.kill_chain_phase("defense-evasion") is KillChainPhase.INSTALLATION


def test_every_tactic_maps_to_a_kill_chain_phase() -> None:
    """A tactic with no mapping would silently drop techniques from that view."""
    for tactic in get_catalogue().tactics():
        assert tactic["shortname"] in TACTIC_TO_KILL_CHAIN, tactic["shortname"]


def test_known_techniques_resolve_with_their_real_names() -> None:
    catalogue = get_catalogue()
    assert catalogue.resolve("T1055").name == "Process Injection"
    assert catalogue.resolve("T1547.001").name == "Registry Run Keys / Startup Folder"
    assert catalogue.resolve("T1490").name == "Inhibit System Recovery"


def test_unknown_techniques_resolve_to_the_parent_then_a_stub() -> None:
    """A stale ID must never silently vanish from the heatmap."""
    catalogue = get_catalogue()
    assert catalogue.resolve("T1055.99999").id == "T1055"

    stub = catalogue.resolve("T9999")
    assert stub.id == "T9999"
    assert "not in ATT&CK" in stub.name


def test_subtechniques_roll_up() -> None:
    catalogue = get_catalogue()
    subs = catalogue.subtechniques_of("T1055")
    assert len(subs) > 5
    assert all(s.parent == "T1055" for s in subs)


def test_technique_kill_chain_uses_the_earliest_tactic() -> None:
    """Techniques sit in several tactics; the earliest keeps stages contiguous."""
    catalogue = get_catalogue()
    # T1547.001 is persistence + privilege-escalation; persistence comes first.
    assert catalogue.kill_chain_for_technique("T1547.001") is KillChainPhase.INSTALLATION


def test_detection_metadata_is_present_for_most_techniques() -> None:
    """The coverage gap check is only useful if MITRE told us what detects what."""
    catalogue = get_catalogue()
    with_codes = [
        t for t in (catalogue.resolve(i) for i in ("T1055", "T1547.001", "T1490", "T1059.001"))
        if t.sysmon_event_codes
    ]
    assert len(with_codes) == 4


def test_every_technique_we_emit_is_in_the_catalogue() -> None:
    """Phase 2 and 3 tag findings by hand; a typo would be invisible otherwise."""
    from necropsy.analysis.capabilities import CATALOGUE as CAPABILITIES
    from necropsy.sandbox.behaviour import LOLBINS

    catalogue = get_catalogue()
    emitted = {t for c in CAPABILITIES for t in c.attack}
    emitted |= {t for t, _label in LOLBINS.values()}
    emitted |= {
        "T1547.001", "T1543.003", "T1055", "T1685", "T1490", "T1071",
        "T1090.001", "T1074.001", "T1027.002", "T1622", "T1027.009", "T1071.001",
    }
    unresolvable = sorted(
        t for t in emitted if "not in ATT&CK" in catalogue.resolve(t).name
    )
    assert not unresolvable, (
        f"technique IDs that resolve to nothing in ATT&CK {catalogue.attack_version}: "
        f"{unresolvable}"
    )

    # Stronger: our own producers should emit *current* IDs, not revoked ones.
    # Following revocations is for other people's rules, not an excuse to rot.
    stale = sorted(t for t in emitted if catalogue.is_revoked(t))
    assert not stale, f"our producers emit revoked technique IDs: {stale}"


def test_revoked_ids_from_other_corpora_still_resolve() -> None:
    """SigmaHQ is full of t1562.001; those rules must stay on the matrix."""
    catalogue = get_catalogue()
    assert catalogue.is_revoked("T1562.001")
    replacement = catalogue.resolve("T1562.001")
    assert replacement.id == "T1685"
    assert replacement.name == "Disable or Modify Tools"
    assert "not in ATT&CK" not in replacement.name
