from __future__ import annotations

from am_assurance.risk.likelihood import _classify, likelihood


def test_boundaries(scoring_config):
    assert _classify(scoring_config, 0.999999) == (0, "Unknown")
    assert _classify(scoring_config, 1.0) == (1, "Low")
    assert _classify(scoring_config, 2.999999) == (1, "Low")
    assert _classify(scoring_config, 3.0) == (2, "Moderate")
    assert _classify(scoring_config, 6.999999) == (2, "Moderate")
    assert _classify(scoring_config, 7.0) == (3, "High")
    assert _classify(scoring_config, 10.999999) == (3, "High")
    assert _classify(scoring_config, 11.0) == (4, "Critical")


def test_product_of_levels(scoring_config):
    # timeliness_level=4, frequency_level=4 -> value=16 -> Critical
    assert likelihood(scoring_config, 4, 4) == (4, "Critical")
    # timeliness_level=0 or frequency_level=0 -> value=0 -> Unknown
    assert likelihood(scoring_config, 0, 3) == (0, "Unknown")
    assert likelihood(scoring_config, 3, 0) == (0, "Unknown")
    # timeliness_level=1, frequency_level=1 -> value=1 -> Low
    assert likelihood(scoring_config, 1, 1) == (1, "Low")


def test_no_gap_across_full_range(scoring_config):
    for hundredth in range(0, 2000):
        value = hundredth / 100.0
        level, label = _classify(scoring_config, value)
        assert level in (0, 1, 2, 3, 4)
        assert label
