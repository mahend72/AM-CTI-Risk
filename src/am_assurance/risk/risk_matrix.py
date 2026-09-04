"""Final qualitative risk matrix. Direct successor to Code/risk_severity.py.txt.

See docs/METHODOLOGY.md "Final risk classification" for the legacy call
convention this preserves (likelihood first, impact second, internally -
this module's public parameter names disambiguate that for callers).
"""

from __future__ import annotations

from am_assurance.core.config import RiskMatrixConfig


def risk_level(risk_matrix_config: RiskMatrixConfig, impact_level: int, likelihood_level: int) -> str:
    """Legacy: risk_severity(level, severity) where `level` received
    likelihood and `severity` received impact - see docs/METHODOLOGY.md.
    Named unambiguously here; behaviour identical."""

    return risk_matrix_config.matrix.get((impact_level, likelihood_level), risk_matrix_config.default_label)
