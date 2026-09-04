from __future__ import annotations

from am_assurance.risk.frequency import frequency_level


def test_boundaries(scoring_config):
    assert frequency_level(scoring_config, 1.999999) == 0
    assert frequency_level(scoring_config, 2.0) == 1
    assert frequency_level(scoring_config, 19.999999) == 1
    assert frequency_level(scoring_config, 20.0) == 2
    assert frequency_level(scoring_config, 39.999999) == 2
    assert frequency_level(scoring_config, 40.0) == 3
    assert frequency_level(scoring_config, 59.999999) == 3
    assert frequency_level(scoring_config, 60.0) == 4


def test_no_gap_across_full_range(scoring_config):
    for hundredth in range(0, 10000):
        value = hundredth / 100.0
        level = frequency_level(scoring_config, value)
        assert level in (0, 1, 2, 3, 4)
