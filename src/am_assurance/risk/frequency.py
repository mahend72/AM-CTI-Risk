"""Frequency factor. Direct successor to Code/find_frequency.py.txt.

See docs/METHODOLOGY.md "Factor: Frequency". The entity-level formula
(len(external_references) * (mean(per-technique frequency) + offset)) is
computed in risk/assessor.py, matching the legacy Estimate_*.py.txt inline
code; this module is only the threshold classifier, matching the legacy
find_frequency.py.txt module boundary 1:1.
"""

from __future__ import annotations

from am_assurance.core.config import ScoringConfig


def frequency_level(scoring_config: ScoringConfig, frequency_value: float) -> int:
    """Legacy: find_frequency(frequency) -> level."""

    for threshold in scoring_config.frequency_thresholds:
        if frequency_value >= threshold.minimum:
            return threshold.level
    raise AssertionError("frequency_thresholds must include a -inf floor")
