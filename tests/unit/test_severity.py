from __future__ import annotations

from am_assurance.risk.severity import severity


def test_unmatched_technique_returns_zero(scoring_config):
    assert severity(scoring_config, "T9999") == (0.0, 0)


def test_single_bucket_match(scoring_config):
    # T0837 only appears in bucket 24 -> base_score 24 -> severity level 1
    base_score, level = severity(scoring_config, "T0837")
    assert base_score == 24.0
    assert level == 1


def test_multi_bucket_average(scoring_config):
    # T0806 appears in buckets 87 and 130 -> mean 108.5 -> level 3
    base_score, level = severity(scoring_config, "T0806")
    assert base_score == (87 + 130) / 2
    assert level == 3


def test_malformed_ids_never_match_real_technique(scoring_config, attack_index):
    """docs/METHODOLOGY_DECISIONS.md D-2: T0381 and T08362 are malformed
    and must never match a real technique id present in the bundle."""

    real_ids = attack_index.all_technique_ids()
    assert "T0381" not in real_ids
    assert "T08362" not in real_ids

    for tid in real_ids:
        assert tid not in ("T0381", "T08362")


def test_severity_thresholds_have_no_gap(scoring_config):
    # Full sweep proving no input in [0, 200] fails to classify.
    from am_assurance.risk.severity import _classify

    for hundredth in range(0, 20000):
        score = hundredth / 100.0
        level = _classify(scoring_config, score)
        assert level in (0, 1, 2, 3, 4)


def test_severity_boundaries(scoring_config):
    from am_assurance.risk.severity import _classify

    assert _classify(scoring_config, 9.999999) == 0
    assert _classify(scoring_config, 10.0) == 1
    assert _classify(scoring_config, 10.000001) == 1
    assert _classify(scoring_config, 39.999999) == 1
    assert _classify(scoring_config, 40.0) == 2
    assert _classify(scoring_config, 79.999999) == 2
    assert _classify(scoring_config, 80.0) == 3
    assert _classify(scoring_config, 119.999999) == 3
    assert _classify(scoring_config, 120.0) == 4
