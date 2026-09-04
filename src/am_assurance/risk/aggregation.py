"""Non-zero mean aggregation. Direct successor to Code/average.py.txt.

See docs/METHODOLOGY.md "Aggregation: non-zero mean".
"""

from __future__ import annotations

from collections.abc import Iterable


def average_nonzero(values: Iterable[float]) -> float:
    """Legacy: average(list) -> mean of non-zero values, or 0 if none."""

    non_zero = [v for v in values if v != 0]
    if not non_zero:
        return 0.0
    return sum(non_zero) / len(non_zero)
