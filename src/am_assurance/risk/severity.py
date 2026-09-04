"""Severity factor. Direct successor to Code/find_severity.py.txt.

See docs/METHODOLOGY.md "Factor: Severity" and
docs/METHODOLOGY_DECISIONS.md D-1/D-2 for why configs/scoring.yaml's
severity_buckets table looks the way it does.
"""

from __future__ import annotations

from am_assurance.core.config import ScoringConfig


def severity(scoring_config: ScoringConfig, technique_id: str) -> tuple[float, int]:
    """Legacy: find_severity(data1, item) -> (avg, severity).

    Returns (base_score, severity_level). base_score is the mean of every
    bucket key whose technique set contains technique_id; 0 if none match.
    """

    matching_buckets = [
        bucket
        for bucket, technique_ids in scoring_config.severity_buckets.items()
        if technique_id in technique_ids
    ]

    if not matching_buckets:
        return 0.0, 0

    base_score = sum(matching_buckets) / len(matching_buckets)
    return base_score, _classify(scoring_config, base_score)


def _classify(scoring_config: ScoringConfig, base_score: float) -> int:
    for threshold in scoring_config.severity_thresholds:
        if base_score >= threshold.minimum:
            return threshold.level
    # Unreachable: the lowest threshold has minimum = -inf.
    raise AssertionError("severity_thresholds must include a -inf floor")
