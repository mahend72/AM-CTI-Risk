"""AI security and assurance extension point.

ARCHITECTURAL EXTENSION ONLY. This package defines data models for a
possible future AI-assurance layer covering AI-enabled Additive
Manufacturing components (e.g. visual quality inspection, predictive
maintenance, generative design). See docs/AI_ASSURANCE_EXTENSION.md.

It performs NO scoring and is NOT wired into src/am_assurance/risk - the
numerical cyber-risk engine (severity, frequency, likelihood, timeliness,
impact, risk_level) is entirely unaffected by anything in this package.
configs/assurance.yaml enforces this at load time
(ai_assurance.affects_risk_score must be false - see
src/am_assurance/core/config.py::AssuranceConfig.load).
"""
