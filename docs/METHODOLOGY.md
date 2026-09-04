# Methodology

This document specifies every scoring factor exactly as implemented in the
original repository (see `docs/CURRENT_IMPLEMENTATION_AUDIT.md` for how this
was reconstructed). Nothing here is new science — it is the existing
methodology made explicit and citable. Where the original provenance of a
threshold or weighting choice is not documented anywhere in the source
repository, this document says so plainly rather than manufacturing a
citation.

## Pipeline overview

```
CTI source (MITRE ATT&CK for ICS, STIX 2.0 bundle)
   -> entity (malware | intrusion-set | course-of-action | campaign)
   -> related attack-pattern techniques (1-hop relationship traversal)
   -> per-technique severity  (severity.py)
   -> per-technique + entity frequency  (frequency.py)
   -> aggregation (non-zero mean)  (aggregation.py)
   -> impact level  (impact.py)
   -> timeliness  (timeliness.py, time-dependent)
   -> likelihood  (likelihood.py, derived from timeliness x frequency)
   -> final qualitative risk  (risk_matrix.py, derived from impact x likelihood)
```

## Factor: Severity

* **Definition**: a per-technique severity score/level derived from a fixed
  lookup table (`data1` in the legacy code) mapping technique IDs to one or
  more numeric "buckets".
* **Source**: `Code/find_severity.py.txt` (legacy) / `risk/severity.py` +
  `configs/scoring.yaml::severity_buckets` (current).
* **Input**: a technique ID string, e.g. `"T0816"`.
* **Rule**:
  1. Find every bucket key `k` whose set of technique IDs contains the
     input.
  2. If none found: `base_score = 0`, `severity_level = 0`.
  3. Else `base_score = mean(matching keys)`, then classify:

     | base_score | severity_level |
     |---|---|
     | `>= 120` | 4 |
     | `[80, 120)` | 3 |
     | `[40, 80)` | 2 |
     | `[10, 40)` | 1 |
     | `< 10` | 0 |
* **Output**: `(base_score: float, severity_level: int 0-4)`.
* **Code module**: `src/am_assurance/risk/severity.py`.
* **Missing-data behaviour**: a technique absent from every bucket returns
  `(0, 0)` — treated as "no known severity evidence", not as an error.
* **Threshold provenance**: *original threshold provenance is not
  documented in the legacy repository.* The bucket values themselves
  (10, 24, 34, 41, 62, 68, 87, 101, 104, 105, 115, 130, 141) and which
  techniques belong to which bucket are asserted directly in the source
  code with no citation, methodology note, or reference to an external
  scoring framework (e.g. CVSS). They are preserved exactly as given.

## Factor: Frequency

Two distinct quantities share this name in the legacy code:

* **Per-technique frequency**: `len(attack_pattern.external_references)` —
  a proxy for "how well-documented/cited is this technique", used only as
  an input to the entity-level frequency below.
* **Entity-level frequency** (the one that is actually scored):
  `frequency_value = len(entity.external_references) * (mean(per-technique frequencies over related techniques) + 1)`,
  with `mean = 0` when the entity has no related techniques. Classified by:

  | frequency_value | frequency_level |
  |---|---|
  | `>= 60` | 4 |
  | `[40, 60)` | 3 |
  | `[20, 40)` | 2 |
  | `[2, 20)` | 1 |
  | `< 2` | 0 |
* **Source**: `Code/find_frequency.py.txt` (classifier) — the entity-level
  formula itself lives inline in each `Estimate_*.py.txt` script (legacy)
  / `risk/assessor.py` (current).
* **Code module**: `src/am_assurance/risk/frequency.py` (classifier) +
  `src/am_assurance/risk/assessor.py` (entity-level formula).
* **Missing-data behaviour**: no related techniques -> `frequency_value =
  len(entity.external_references) * 1` (mean defaults to 0, `+1` still
  applied).
* **Threshold provenance**: not documented in the legacy repository.

## Factor: Timeliness

* **Definition**: how recently the entity's `modified` STIX timestamp was
  updated, expressed in elapsed weeks from an assessment reference time,
  and inverted (recent = higher timeliness level).
* **Source**: `Code/find_timeliness.py.txt` (legacy) / `risk/timeliness.py`
  (current).
* **Input**: `like = (as_of - modified_timestamp) / 86400 / 7` (weeks).
  In the legacy code `as_of` is always `time.time()` evaluated at script
  execution — i.e. "now". The refactor exposes `as_of` as an explicit,
  injectable parameter (defaulting to "now") purely for reproducibility;
  the formula itself is unchanged. See `docs/REPRODUCIBILITY.md`.
* **Rule**:

  | like (weeks) | timeliness_level |
  |---|---|
  | `<= 20` | 4 |
  | `(20, 35]` | 3 |
  | `(35, 50]` | 2 |
  | `(50, 60]`\* | 1 |
  | `>= 60` | 0 |

  \* At `like == 60` exactly, both the level-1 and level-0 branches match
  in the legacy code (see `docs/LEGACY_BEHAVIOUR.md` §3); the legacy
  behaviour deterministically resolves to level 0 at that exact point, and
  that exact behaviour is preserved.
* **Output**: `timeliness_level: int 0-4`.
* **Missing-data behaviour**: not applicable — every STIX object in the
  bundle carries a `modified` timestamp.
* **Threshold provenance**: not documented in the legacy repository.

## Factor: Likelihood

* **Definition**: derived signal combining timeliness and frequency.
* **Source**: `Code/find_likelihood.py.txt` (legacy) / `risk/likelihood.py`
  (current).
* **Input**: `value = timeliness_level * frequency_level` (integer product,
  range 0-16).
* **Rule**:

  | value | likelihood_level | label |
  |---|---|---|
  | `>= 11` | 4 | Critical |
  | `[7, 11)` | 3 | High |
  | `[3, 7)` | 2 | Moderate |
  | `[1, 3)` | 1 | Low |
  | `< 1` | 0 | Unknown |
* **Output**: `(likelihood_level: int, label: str)`.
* **Threshold provenance**: not documented in the legacy repository.

## Aggregation: non-zero mean

* **Definition**: mean of a list of per-technique `base_score` values,
  excluding zero-valued entries from both the sum and the count.
* **Source**: `Code/average.py.txt` (legacy) / `risk/aggregation.py`
  (current).
* **Rule**: `mean(x for x in values if x != 0)`, or `0` if no non-zero
  values exist.
* **Missing-data behaviour**: an entity with no related techniques, or
  whose related techniques all score 0, produces `impact_score = 0`.
* **Rationale (undocumented in legacy)**: excluding zero-scored techniques
  from the denominator means an entity's impact score reflects only the
  techniques for which severity evidence exists, rather than being diluted
  by unscored techniques. This interpretation is inferred from the code's
  behaviour, not stated anywhere in the original repository.

## Factor: Impact level

* **Definition**: classifies the aggregated `impact_score` into a
  qualitative level, using the same four cut-points as severity (120/80/
  40/10).
* **Source**: `Code/Impact_level.py.txt` (legacy, function name
  `impact_level`, parameter name `max_val` — misleadingly named; it
  receives the *mean* impact score, not a maximum) / `risk/impact.py`
  (current).
* **Rule** (as corrected — see `docs/METHODOLOGY_DECISIONS.md` D-4 for why
  and confirmation that this changes zero existing results):

  | impact_score | impact_level | label |
  |---|---|---|
  | `>= 120` | 4 | Very Critical |
  | `[80, 120)` | 3 | Critical |
  | `[50, 80)` | 2 | Hazardous |
  | `[10, 50)` | 1 | Certain Hazard |
  | `< 10` | 0 | Not Hazard |
* **Output**: `(impact_level: int 0-4, label: str)`.
* **Threshold provenance**: not documented in the legacy repository.

## Final risk classification

* **Definition**: a fixed lookup matrix combining impact level and
  likelihood level into a final qualitative rating.
* **Source**: `Code/risk_severity.py.txt` (legacy, function signature
  `risk_severity(level, severity)`) / `risk/risk_matrix.py` (current).
* **Call convention** (preserved exactly): the caller passes
  `risk_severity(likelihood_level, impact_level)` — i.e. the parameter
  named `level` receives *likelihood*, and the parameter named `severity`
  receives *impact level*. This is unintuitive naming inherited from the
  legacy code; the refactor keeps the same call convention internally and
  names the public function arguments unambiguously
  (`impact_level`, `likelihood_level`) to avoid the same confusion going
  forward, without changing which value maps to which output.
* **Matrix** (18 of 25 combinations mapped; the remaining 7 — every
  combination where impact level is in {0,1,2,3} and likelihood is 0 (with
  the addition of impact 0 with likelihood 1,2,3) — fall through to
  `"Unknown"`, exactly as legacy):

  | impact \\ likelihood | 0 | 1 | 2 | 3 | 4 |
  |---|---|---|---|---|---|
  | **0** | Unknown | Unknown | Unknown | Unknown | Low |
  | **1** | Unknown | Low | Low | Low | Moderate |
  | **2** | Unknown | Low | Moderate | Moderate | High |
  | **3** | Unknown | Low | Moderate | High | High |
  | **4** | Low | Moderate | High | High | Critical |

  (Row = impact level i.e. the `severity` argument to `risk_severity`;
  column = likelihood level i.e. the `level` argument.)
* **Code module**: `src/am_assurance/risk/risk_matrix.py` +
  `configs/risk_matrix.yaml`.
* **Threshold provenance**: not documented in the legacy repository.

## Entity-technique relationship rule

An entity (malware / intrusion-set / course-of-action / campaign) is
related to an `attack-pattern` if a STIX `relationship` object exists with
`source_ref == entity.id` **and** `target_ref` resolves to an object of
type `attack-pattern`, regardless of the relationship's `relationship_type`
(`mitigates`, `uses`, `detects`, or `revoked-by` are all accepted — the
legacy code never filters on this field). This is preserved exactly; see
`docs/CURRENT_IMPLEMENTATION_AUDIT.md` §2.

## Entities covered

`malware`, `intrusion-set`, `course-of-action` were scored by the legacy
scripts. `campaign` (1 object in the bundle) was never scored by any legacy
script — there is no regression oracle for it. The generic assessor
supports it using the identical rule set, but this is a **new application
of the existing methodology to a previously-unscored entity type**, not a
change to the methodology itself, and is labelled as such in output
(`"legacy_validated": false` on campaign records — see `pipeline.py`).
