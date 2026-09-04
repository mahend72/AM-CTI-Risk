# Reference data

- **`technique_mapping.csv`** — a plain export of `configs/scoring.yaml`'s
  `severity_buckets` table (technique ID -> severity bucket). This is
  *existing* data reproduced for human inspection; it is not read by any
  code path (the runtime source of truth is `configs/scoring.yaml`). See
  `docs/METHODOLOGY.md` for what it means.

- **`am_asset_mapping.csv`** — an **empty template**, header only. The
  original repository never mapped ATT&CK techniques to specific Additive
  Manufacturing assets or process stages in code — the AM framing exists
  only at the paper/narrative level (see
  `docs/CURRENT_IMPLEMENTATION_AUDIT.md` §15). Fabricating rows here would
  be inventing scientific data, which the restructuring brief explicitly
  forbids. `src/am_assurance/cti/technique_mapping.py::am_asset_context()`
  reads this file if and when it is curated, and returns `None` for every
  technique until then. It is never consulted by the risk engine — it
  exists purely as a future, evidence-layer enrichment point.
