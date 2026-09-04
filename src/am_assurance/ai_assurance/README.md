# ai_assurance — architectural extension point (not active)

This package exists so the repository's *shape* already supports future AI
security and assurance work on AI-enabled Additive Manufacturing systems.
It currently contains **schemas and interfaces only**:

- `models.py` — `AIComponent`, `AIThreatEvidence` dataclasses.
- `threat_mapping.py` — stub loader (`NotImplementedError`) documenting
  where a future MITRE ATLAS / OWASP GenAI Security Project / NIST AI RMF
  ingestion path would live, plus one genuinely-implemented pure filter
  function that operates only on caller-supplied data.

**It performs no scoring.** Nothing in `src/am_assurance/risk/` (the
legacy-equivalent cyber-risk engine: severity, frequency, likelihood,
timeliness, impact, risk_level) imports from this package, and
`configs/assurance.yaml` refuses to load if `ai_assurance.affects_risk_score`
is set to `true` (see `core/config.py::AssuranceConfig.load`).

Full architecture and roadmap: `docs/AI_ASSURANCE_EXTENSION.md`.
Tests proving this package cannot influence the cyber-risk engine's
outputs: `tests/regression/test_ai_assurance_isolation.py`.
