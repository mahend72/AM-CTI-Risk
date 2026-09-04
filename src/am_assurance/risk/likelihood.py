"""Likelihood factor. Direct successor to Code/find_likelihood.py.txt.

See docs/METHODOLOGY.md "Factor: Likelihood".
"""

from __future__ import annotations

from am_assurance.core.config import ScoringConfig


def likelihood(scoring_config: ScoringConfig, timeliness_level: int, frequency_level: int) -> tuple[int, str]:
    """Legacy: find_likelihood(timeliness_level * frequency_level) -> (level, label)."""

    value = timeliness_level * frequency_level
    return _classify(scoring_config, value)


def _classify(scoring_config: ScoringConfig, value: float) -> tuple[int, str]:
    for threshold in scoring_config.likelihood_thresholds:
        if value >= threshold.minimum:
            return threshold.level, threshold.label
    raise AssertionError("likelihood_thresholds must include a -inf floor")
