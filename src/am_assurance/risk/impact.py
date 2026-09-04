"""Impact classification. Direct successor to Code/Impact_level.py.txt.

See docs/METHODOLOGY.md "Factor: Impact level" and
docs/METHODOLOGY_DECISIONS.md D-4: this is the ONE place in the
restructured codebase where a boundary operator differs from the literal
legacy source (lower bounds made inclusive to remove an UnboundLocalError
at max_val in {10, 50, 80}). Verified to change zero of 93 pre-existing
results - see tests/regression/test_legacy_comparison.py.
"""

from __future__ import annotations

from am_assurance.core.config import ScoringConfig


def impact_level(scoring_config: ScoringConfig, impact_score: float) -> tuple[int, str]:
    """Legacy: impact_level(max_val) -> (level_0, level_1)."""

    for threshold in scoring_config.impact_thresholds:
        if impact_score >= threshold.minimum:
            return threshold.level, threshold.label
    raise AssertionError("impact_thresholds must include a -inf floor")
