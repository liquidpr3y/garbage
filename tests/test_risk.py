"""The shared risk vocabulary -- the piece both GUI panels render through."""

from __future__ import annotations

from necropsy.contracts.risk import RiskBand, RiskFactor, band_for, score_factors


def test_mitigating_factors_lower_the_score() -> None:
    base = 5.0
    aggravated = score_factors(base, [RiskFactor(code="a", label="a", weight=2.0)])
    mitigated = score_factors(
        base, [RiskFactor(code="b", label="b", weight=2.0, direction=-1)]
    )
    assert aggravated.value == 7.0
    assert mitigated.value == 3.0


def test_score_is_clamped_to_the_band_range() -> None:
    high = score_factors(9.0, [RiskFactor(code="a", label="a", weight=10.0)])
    low = score_factors(0.5, [RiskFactor(code="b", label="b", weight=9.0, direction=-1)])
    assert high.value == 10.0 and high.band is RiskBand.SEVERE
    assert low.value == 0.0 and low.band is RiskBand.MINIMAL


def test_bands_are_monotonic() -> None:
    order = [
        RiskBand.MINIMAL, RiskBand.LOW, RiskBand.MODERATE, RiskBand.HIGH, RiskBand.SEVERE
    ]
    seen = [band_for(v) for v in (0, 1.9, 2, 3.9, 4, 6.4, 6.5, 8.4, 8.5, 10)]
    assert [order.index(b) for b in seen] == sorted(order.index(b) for b in seen)


def test_factors_are_carried_onto_the_score() -> None:
    """The operator is accepting blast radius, so the reasons travel with the number."""
    factors = [
        RiskFactor(code="egress_allowed", label="Live egress", weight=3.0),
        RiskFactor(code="network_isolated", label="Host-only", weight=1.0, direction=-1),
    ]
    score = score_factors(5.0, factors)
    assert [f.code for f in score.factors] == ["egress_allowed", "network_isolated"]
    assert score.value == 7.0
