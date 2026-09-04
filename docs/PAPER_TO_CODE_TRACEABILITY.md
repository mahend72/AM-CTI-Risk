# Paper → Code Traceability

Status legend: **Ready** (paper content fully known, safe to implement) ·
**Blocked** (paper content missing per `MISSING_METHODOLOGY_INPUTS.md`,
implementation must not proceed) · **Scaffolded** (module/signature exists
as a stub, body intentionally raises `NotImplementedError` referencing the
blocking doc) · **N/A** (reference/documentation, not code).

| Paper section | Equation/Table | Scientific component | Code module | Test | Status |
|---|---|---|---|---|---|
| §4.1 | Fig. 3 (categories) | 7 threat categories | `src/am_cti_risk/core/models.py` (category enum), `data/reference/am_threats.csv` | `tests/unit/test_am_threats_catalogue.py` | Ready |
| §4.2 | Table 1 | Characteristic → numeric value mapping | `src/am_cti_risk/impact/characteristics.py`, `configs/impact.yaml` | — | Blocked |
| §4.3 | Table 2, Fig. 4 | 22 threats × 5 characteristics (qualitative) | `data/reference/am_threats.csv`, `src/am_cti_risk/cti/mappings.py` | `tests/unit/test_am_threats_catalogue.py` | Ready (best-effort transcription — see extraction doc caveats) |
| §4.4 | Eq. (1), Table 4 | Threat impact decay | `src/am_cti_risk/impact/decay.py::calculate_decay` | `tests/unit/test_decay.py` (stub only: asserts `NotImplementedError`) | Scaffolded |
| §4.5 | Eq. (2) | Impact aggregation (weighted sum of 5 characteristics) | `src/am_cti_risk/impact/aggregation.py::calculate_aggregate_impact` | `tests/unit/test_aggregation.py` (stub) | Scaffolded |
| §4.5 | Eq. (3), Table 5 | Decayed overall impact + impact-level classification | `src/am_cti_risk/impact/aggregation.py`, `src/am_cti_risk/impact/classifier.py::classify_impact` | `tests/unit/test_classifier.py` (stub) | Scaffolded |
| §5 | Eq. (4) | Likelihood formulation (weighted) | `src/am_cti_risk/likelihood/aggregation.py::calculate_likelihood` | `tests/unit/test_likelihood_aggregation.py` (stub) | Scaffolded |
| §5 | Eq. (5) | Likelihood formulation (equal-weight experimental case) | same module, alternate weight config | same | Scaffolded |
| §5.1 | Eq. (6), Table 6 | Source reliability aggregate | `src/am_cti_risk/likelihood/reliability.py::calculate_source_reliability` | `tests/unit/test_reliability.py` (stub) | Scaffolded |
| §5.1 | (extensiveness definition) | Extensiveness sub-metric | `src/am_cti_risk/likelihood/extensiveness.py` | `tests/unit/test_extensiveness.py` | Ready-ish (ratio formula low-risk to implement; flagged for verification — see extraction doc §7) |
| §5.1 | (timeliness definition) | Timeliness sub-metric | `src/am_cti_risk/likelihood/timeliness.py` | `tests/unit/test_timeliness.py` (stub) | Blocked (multiple formulas match the prose description) |
| §5.1 | (completeness definition) | Completeness sub-metric | `src/am_cti_risk/likelihood/completeness.py` | `tests/unit/test_completeness.py` | Ready-ish (ratio formula low-risk; flagged for verification) |
| §5.2 | Eq. (7), Table 7 | IOC/threat severity aggregation | `src/am_cti_risk/likelihood/severity.py::calculate_severity` | `tests/unit/test_likelihood_severity.py` (stub) | Scaffolded |
| §5.3 | Eq. (8), Tables 8–9 | Occurrence/frequency | `src/am_cti_risk/likelihood/occurrence.py::calculate_occurrence` | `tests/unit/test_occurrence.py` (stub) | Scaffolded |
| §6 | Eq. (9) | Final risk calculation | `src/am_cti_risk/risk/calculator.py::calculate_risk` | `tests/unit/test_risk_calculator.py` (stub) | Scaffolded |
| §6 | Table 10 | Risk matrix (impact × likelihood → risk level) | `src/am_cti_risk/risk/matrix.py`, `configs/risk_matrix.yaml` | `tests/unit/test_risk_matrix.py` (stub; would assert full 5×5 coverage once populated) | Blocked — critical |
| §7.1 | Table 11 | Reference impact/likelihood results per threat | `results/validation/paper_table11_reference.csv` (reference fixture, not code) | `tests/regression/test_paper_table11.py` (stub) | Blocked |
| §7.1 | Table 12 + ranking rule | Risk score/level/rank per threat; ranking logic | `src/am_cti_risk/risk/ranking.py::rank_threats` | `tests/regression/test_paper_table12.py` (ordinal-only sanity checks possible now; full regression blocked) | Ranking rule Ready; full regression data Blocked |
| §7.2 | Table 13 | CVE dataset characteristics | `src/am_cti_risk/cti/cve_loader.py` (loader), `docs/DATA_DICTIONARY.md` | `tests/integration/test_cve_loader.py` | Loader Ready to scaffold; needs an actual CVE data file to run against |
| §7.2–7.3 | Table 14 | CVE validation results | `src/am_cti_risk/validation/cve_validation.py::validate_against_cves` | `tests/regression/test_cve_validation.py` (stub) | Blocked (CVSS→framework mapping unknown) |
| §7.4 / §8 | — | Comparisons, limitations | `docs/LIMITATIONS.md` | N/A | N/A (documentation) |
| — | — | Provenance / audit record for every assessment | `src/am_cti_risk/provenance/audit_record.py`, `run_metadata.py` | `tests/integration/test_audit_record.py` | Ready (provenance is a software concern, not a paper value — can be built now against scaffolded fields) |
| — | — | Run orchestration | `src/am_cti_risk/pipeline.py`, `scripts/run_assessment.py` | `tests/integration/test_pipeline_stub.py` | Ready to scaffold; will only produce placeholder/blocked-labelled output until the above are unblocked |

## Reading this table

Of 19 scientific rows (excluding the two pure-documentation/software
rows), **3 are Ready**, **2 are "Ready-ish"** (formula is low-risk to
implement from the verbal description but explicitly flagged for
verification against the real equation before being trusted), and
**14 are Blocked or Scaffolded-pending-data**. This is the same picture as
`docs/MISSING_METHODOLOGY_INPUTS.md` §"Equations" and §"Tables", presented
per-module instead of per-paper-element.
