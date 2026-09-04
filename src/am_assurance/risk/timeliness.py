"""Timeliness factor. Direct successor to Code/find_timeliness.py.txt.

See docs/METHODOLOGY.md "Factor: Timeliness" and
docs/METHODOLOGY_DECISIONS.md D-3. This implementation deliberately
reproduces the legacy five-independent-conditionals structure (evaluated
in the configured order, last match wins) rather than an if/elif chain,
so that the documented overlap at like == 60 continues to resolve to
level 0 exactly as the legacy code does. See
docs/LEGACY_BEHAVIOUR.md §3 and tests/unit/test_timeliness.py.
"""

from __future__ import annotations

from am_assurance.core.config import ScoringConfig


def timeliness_level(scoring_config: ScoringConfig, like_weeks: float) -> int:
    """Legacy: find_timeliness(like) -> severity (renamed timeliness_level
    here to avoid confusion with the unrelated severity factor)."""

    level = None
    for rule in scoring_config.timeliness_rules:
        matched = _matches(rule, like_weeks)
        if matched:
            level = rule.level
    if level is None:
        raise AssertionError("timeliness_rules did not cover like_weeks; check configs/scoring.yaml")
    return level


def _matches(rule, like_weeks: float) -> bool:
    if rule.op == "<=":
        ok = like_weeks <= rule.value
        if rule.gt is not None:
            ok = ok and like_weeks > rule.gt
        return ok
    if rule.op == ">=":
        return like_weeks >= rule.value
    raise AssertionError(f"unknown timeliness rule op: {rule.op}")


def like_weeks_since(modified_epoch_seconds: float, as_of_epoch_seconds: float) -> float:
    """Legacy: like = (time.time() - mod_date.timestamp()) / 86400 / 7.

    `as_of_epoch_seconds` defaults to "now" at the call site (see
    risk/assessor.py) but is always passed explicitly here so this
    function has no hidden dependency on wall-clock time - see
    docs/REPRODUCIBILITY.md.
    """

    return (as_of_epoch_seconds - modified_epoch_seconds) / 86400 / 7
