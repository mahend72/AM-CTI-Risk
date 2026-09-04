# Current Implementation Audit

Status: **PHASE A output.** This document reconstructs the behaviour of the
repository exactly as it existed before restructuring (commit `b6e52b4`,
"LICENCE"). It is the ground truth against which every refactored module is
regression-tested. Nothing in this document is aspirational — every claim
below was verified by reading the original source or executing it against
`data/raw/ics-attack.json` (formerly `ics-attack.json`) and the pre-computed
outputs in `legacy/original_results/`.

## 1. Original repository structure

```
README.md                          project blurb
LICENCE.txt
User-guide.md.txt                  empty (0 bytes)
ics-attack.json                    MITRE ATT&CK for ICS STIX 2.0 bundle (1008 objects)
Code/*.py.txt                      10 script files (see below), saved as .txt so not
                                    directly executable with `python file.py`
Results/COA.json                   51 pre-computed course-of-action assessments
Results/intrusion_set.json         15 pre-computed intrusion-set assessments
Results/malware.json               27 pre-computed malware assessments
campaign/, course-of-action/,
identity/, intrusion-set/,
malware/, marking-definition/,
x-mitre-data-source/               loose per-object STIX JSON files (a partial
                                    extraction of individual objects from
                                    ics-attack.json). No script in Code/ opens
                                    any file in these folders — they are
                                    unused by the pipeline. x-mitre-data-source/
                                    holds only 3 of the 17 such objects present
                                    in the bundle, confirming it is a partial,
                                    stale extract rather than authoritative data.
```

### Code/ inventory

| File | Role |
|---|---|
| `find_severity.py.txt` | Defines the `data1` frequency-bucket table and `find_severity(data1, item)` |
| `find_frequency.py.txt` | `find_frequency(frequency) -> level` |
| `find_likelihood.py.txt` | `find_likelihood(value) -> (level, label)` |
| `find_timeliness.py.txt` | `find_timeliness(like) -> level` |
| `Impact_level.py.txt` | `impact_level(max_val) -> (level, label)` |
| `risk_severity.py.txt` | `risk_severity(level, severity) -> label` |
| `average.py.txt` | `average(list) -> float`, mean of non-zero values |
| `Estimate_malware.py.txt` | End-to-end script for `type == 'malware'` entities |
| `Estimate_intrusion_set.py.txt` | End-to-end script for `type == 'intrusion-set'` entities |
| `Estimate_courseOfaction.py.txt` | End-to-end script for `type == 'course-of-action'` entities |

**No entity script exists for `campaign`**, even though a single `campaign`
object exists in the bundle. The original methodology was never extended to
that type. The restructured pipeline supports `campaign` generically (same
code path as the other three) but this audit records that campaign scoring
was **not** part of the validated legacy behaviour — there is no
`legacy/original_results/campaign.json` to regression-test against.

## 2. Execution flow (as originally written)

None of the `Estimate_*.py.txt` files import anything from the other files.
Each one calls `find_severity`, `average`, `impact_level`, `find_timeliness`,
`find_frequency`, `find_likelihood`, `risk_severity`, and references `data1`
as if they were already defined in the running interpreter. **The scripts do
not run standalone.** The only way to reproduce the original pipeline is to
execute all ten files in one shared namespace (e.g. paste them in order into
one script/notebook) before running `Estimate_*.py.txt`. This is a
reproducibility defect (see §19) — not a scientific one. The restructured
`am_assurance` package makes these dependencies explicit imports; the
*computation* each function performs is unchanged (verified below).

For a given entity type (`malware`, `intrusion-set`, `course-of-action`),
each script performs, per entity object `obj1`:

1. Record `source_id`, `created`, `modified`.
2. **Find related techniques** — scan *every* `relationship` object in the
   bundle; keep those with `source_ref == obj1['id']`; for each, scan *every*
   object again to find the `attack-pattern` whose `id == target_ref`. This
   is an unindexed O(n·m) triple-nested scan repeated per entity
   (documented as a performance defect, §14/§19 — not a scientific one,
   since the *result* of "which attack-patterns does this entity relate to"
   is unchanged by indexing).
   Relationship type is **not** filtered (`mitigates`/`uses`/`detects`/
   `revoked-by` are all accepted) — the selection is entirely governed by
   the *target object's type* being `attack-pattern`. This matters:
   the new implementation must reproduce this exact selection rule rather
   than "only take `mitigates` for course-of-action / only `uses` for
   malware and intrusion-set", which would silently change results.
3. For each related attack-pattern, look up its `mitre-attack` external
   reference to get the technique code (e.g. `T0816`), then:
   * `base_score, severity = find_severity(data1, technique_code)`
   * `frequency = len(attack_pattern['external_references'])`
   (this per-technique "frequency" is the technique's own reference count,
   *not* related to the entity-level frequency computed later)
4. `impact_score = average([m['base_score'] for m in mitigations])` — mean of
   the **non-zero** base scores across all related techniques (see `average`
   semantics, §9).
5. `impact_level(impact_score) -> (severity_level, severity_label)`.
6. Entity-level `frequency = len(obj1['external_references']) * (avg(m['frequency'] for m in mitigations) + 1)`,
   with `avg = 0` if there are no mitigations.
7. `like = (time.time() - modified_timestamp) / 86400 / 7` — elapsed weeks
   since the entity's `modified` date, **evaluated at script run time**.
8. `timeliness_level = find_timeliness(like)`.
9. `frequency_level = find_frequency(frequency)`.
10. `likelihood_level, likelihood_label = find_likelihood(timeliness_level * frequency_level)`.
11. `risk_level = risk_severity(likelihood_level, severity_level)`.
12. Append the assembled record to `results`; after the loop, dump the list
    to `COA.json` / `intrusion_set.json` / `malware.json`.

**Important reproducibility property**: steps 7–11 depend on `time.time()`
at execution. Re-running the original scripts on a different day produces
different `timeliness`, `frequency` level is *not* time-dependent (it only
uses static reference counts), but `timeliness`, `likelihood`, and
`risk_level` *are* time-dependent. `severity`, `impact_score`,
`impact_level`, and `frequency` are time-invariant and were used as the
exact-match regression oracle (`legacy/original_results/*.json`) — see
`docs/REPRODUCIBILITY.md`.

## 3. Input data

`ics-attack.json` — MITRE ATT&CK for ICS, STIX 2.0 bundle, 1008 objects:

| type | count |
|---|---|
| relationship | 755 |
| attack-pattern | 91 |
| course-of-action | 51 |
| x-mitre-data-component | 36 |
| malware | 27 |
| x-mitre-data-source | 17 |
| intrusion-set | 15 |
| x-mitre-tactic | 12 |
| x-mitre-matrix | 1 |
| campaign | 1 |
| identity | 1 |
| marking-definition | 1 |

Relationship types present: `mitigates` (315), `detects` (231), `uses` (207),
`revoked-by` (2).

Of the 91 `attack-pattern` objects, **79 distinct `mitre-attack` technique
IDs** are represented (some attack-patterns are sub-techniques or share
external IDs) and **12 attack-patterns have no `mitre-attack` external
reference at all** (they are historical/renamed technique objects — e.g.
"Change Program State", "Modify Control Logic"). This is relevant to a
defect discussed in §13.

## 4. Entity relationships (as used by the pipeline)

```
course-of-action  --(relationship, any type, target is attack-pattern)-->  attack-pattern
intrusion-set     --(relationship, any type, target is attack-pattern)-->  attack-pattern
malware           --(relationship, any type, target is attack-pattern)-->  attack-pattern
attack-pattern    --(external_references[mitre-attack].external_id)-->     technique code (e.g. T0816)
```

No relationship is ever traversed further than one hop; the pipeline never
uses `intrusion-set --uses--> malware` or `course-of-action --mitigates-->`
chains of length > 1.

## 5. Severity calculation

`Code/find_severity.py.txt` defines a literal dict `data1` mapping an
integer "frequency bucket" to a `set` of technique codes it was manually
observed to contain, e.g.:

```python
data1 = {
  141: {"T0801", "T0842", "T0856", "T0877", "T0835"},
  115: {"T0800", "T0857", ...},
  ...
}
```

`find_severity(data1, item)`:
1. Collect every bucket-key `k` such that `item in data1[k]`.
2. If none: `avg = 0`, `severity = 0`.
3. Else: `avg = mean(keys)`; classify by threshold:
   `avg>=120 -> 4`, `80<=avg<120 -> 3`, `40<=avg<80 -> 2`, `10<=avg<40 -> 1`,
   `avg<10 -> 0`.
4. Returns `(avg, severity)` — `avg` is stored as `base_score`.

**No documented provenance** exists anywhere in the repository for how the
bucket values (141, 115, 62, 24, 87, 130, 34, 101, 68, 104, 41, 105, 10) or
the technique-to-bucket assignments were derived. This audit does not
invent one. See `docs/METHODOLOGY.md`.

**Defect found**: `data1` is a Python dict *literal* with duplicate keys
(`34` appears twice, `10` appears three times). Python keeps only the
*last* occurrence of a duplicate literal key — this is standard, silent
Python behaviour, not a runtime crash. The practical effect: the intended
bucket `34: {"T0800", "T0857", "T0839", "T0862"}` is completely discarded
and replaced by `34: {"T08362", "T0889", "T0879"}`. See
`docs/LEGACY_BEHAVIOUR.md` §1 for the full before/after table and
`docs/METHODOLOGY_DECISIONS.md` D-1 for the disposition (preserved exactly,
not corrected).

**Defect found**: two technique identifiers in `data1` — `"T0381"` and
`"T08362"` — do not match the format of any real ATT&CK-for-ICS technique
ID and are absent from all 79 valid technique IDs present in
`ics-attack.json`. They are inert: `find_severity` never matches them
against a real technique, so they contribute nothing to any score. See
`docs/LEGACY_BEHAVIOUR.md` §2 / `docs/METHODOLOGY_DECISIONS.md` D-2.

## 6. Frequency calculation

Two distinct notions share the name "frequency" in the original code —
this audit calls them out explicitly because it is easy to conflate them:

* **Per-technique frequency** (`mit['frequency']`): `len(attack_pattern['external_references'])`
  — how many external references (citations) a technique has.
* **Per-entity frequency** (`res['frequency']`, the one that feeds
  `find_likelihood`): `len(entity['external_references']) * (mean(per-technique frequencies) + 1)`,
  classified through `find_frequency`:
  `>=60 -> 4`, `40<=f<60 -> 3`, `20<=f<40 -> 2`, `2<=f<20 -> 1`, `f<2 -> 0`.

Both are static (derived from the STIX bundle only) — **not** time-dependent.

## 7. Likelihood calculation

`find_likelihood(value)` where `value = timeliness_level * frequency_level`
(product of two small integers 0–4, so `value` ranges 0–16):
`>=11 -> (4, "Critical")`, `7<=v<11 -> (3, "High")`, `3<=v<7 -> (2, "Moderate")`,
`1<=v<3 -> (1, "Low")`, `v<1 -> (0, "Unknown")`.

## 8. Timeliness calculation

`like = (time.time() - modified_ts) / 86400 / 7` (elapsed weeks since the
entity was last modified in the source data), classified by
`find_timeliness`: `like<=20 -> 4`, `20<like<=35 -> 3`, `35<like<=50 -> 2`,
`50<like<=60 -> 1`, `like>=60 -> 0`.

**Defect found**: at exactly `like == 60`, both the `<=60 and >50` branch
(level 1) and the `>=60` branch (level 0) evaluate `True` because the
function uses independent `if` statements rather than `if/elif`. The
second statement executes after the first and overwrites the result, so
`like == 60` deterministically resolves to level 0 — but only because of
statement order, not because the ranges were designed not to overlap. This
does not crash. See `docs/LEGACY_BEHAVIOUR.md` §3 / decision D-3 (preserved
exactly).

Time-dependence means `timeliness`, and everything downstream of it
(`likelihood`, `risk_level`), is **not reproducible** across runs on
different dates unless the "current time" is pinned. See §19 and
`docs/REPRODUCIBILITY.md`.

## 9. Aggregation (`average`)

```python
def average(list):
    non_zero = [i for i in list if i != 0]
    return sum(non_zero) / len(non_zero) if non_zero else 0
```

Mean of **non-zero** values only; zeros (i.e. techniques with no `data1`
match) are excluded from the denominator entirely, not treated as 0-valued
data points. An empty list, or a list of all zeros, returns `0`.

## 10. Impact classification

`impact_level(max_val)` (the parameter name is misleading — it receives
the *impact_score*, i.e. `average(base_scores)`, not a maximum) buckets
using the *same four cut-points as `find_severity`* (120/80/40/10) but with
inconsistent boundary operators:

```python
if max_val >= 120:            level 4  "Very Critical"
if max_val < 120 and max_val > 80:   level 3  "Critical"
if max_val < 80 and max_val > 50:    level 2  "Hazardous"
if max_val < 50 and max_val > 10:    level 1  "Certain Hazard"
if max_val < 10:                     level 0  "Not Hazard"
```

**Defect found (crash risk)**: at `max_val` exactly equal to `10`, `50`, or
`80`, *no* branch is `True` (each branch's lower bound is a strict `>`, but
the adjacent branch's upper bound is a strict `<`, leaving the exact
boundary value covered by neither). `level_0`/`level_1` are never assigned,
and the function raises `UnboundLocalError` on `return level_0, level_1`.
This is a genuine implementation defect per the "unhandled boundary"
category. Verified against all 93 entities in
`legacy/original_results/*.json`: **no existing entity's `impact_score`
lands exactly on 10, 50, or 80**, so this defect has never fired against
this dataset, but it remains a live crash risk for any future data. See
`docs/METHODOLOGY_DECISIONS.md` D-4 for the correction applied (aligning
the boundary operators with `find_severity`'s already-consistent `>=`
pattern over the identical four cut-points) and the regression evidence
that this correction changes **zero** of the 93 existing results.

## 11. Final risk matrix

`risk_severity(level, severity)` where `level` = impact level (0–4) and
`severity` = likelihood level (0–4) — **note the parameter names in the
original function are the reverse of what they represent relative to the
caller**: `risk_severity(likelihood[0], severity[0])` passes *likelihood*
as the argument named `level`, and *impact severity* as the argument
named `severity`. This is confusing but not a defect — the function body
is internally consistent with how it is called everywhere in the original
code. This audit documents the call convention precisely (§13) so the
refactor cannot silently transpose the two arguments.

18 of 25 `(level, severity)` combinations are explicitly mapped to
`Critical`/`High`/`Moderate`/`Low`; the remaining 7 combinations
(`level in {0,1,2,3}` paired with the *lowest* severities, e.g. `(0,0)`,
`(1,0)`, `(2,0)`, `(3,0)`, `(0,1)`, `(0,2)`, `(0,3)`) fall through to the
final `else` and return `"Unknown"`. This is a deliberate partial mapping,
not a defect — it is preserved exactly.

## 12. Outputs

`Results/{COA,intrusion_set,malware}.json` — a flat JSON array per entity
type, one object per entity, containing the identifying fields, the full
list of related-technique records (`mitigates`/`uses`), and the final
`impact_score`, `impact_level`, `timeliness`, `frequency`, `likelihood`,
`risk_level`. These three files (now under `legacy/original_results/`) are
the regression oracle for this restructuring.

## 13. Implementation defects (summary)

| # | Defect | Category | Crashes today? | Disposition |
|---|---|---|---|---|
| D-1 | Duplicate literal keys in `data1` (`34`, `10`) silently collapse | Duplicate dictionary key | No | Preserved exactly — see `METHODOLOGY_DECISIONS.md` |
| D-2 | Malformed technique IDs `T0381`, `T08362` in `data1` | Malformed identifier | No (inert, never matches) | Preserved exactly, flagged in validation report |
| D-3 | `find_timeliness` boundary overlap at `like==60` (independent ifs, not elif) | Unhandled/ambiguous boundary | No (deterministic via statement order) | Preserved exactly |
| D-4 | `impact_level` undefined at `max_val` in {10, 50, 80} | Unhandled boundary / crash risk | No (never hit by current 93 entities) | **Corrected** (boundary operators aligned with `find_severity`); zero result change confirmed |
| D-5 | 12 `attack-pattern` objects lack a `mitre-attack` external reference; original nested loop would append a `mit` dict missing `base_score`/`severity`/`frequency` keys, causing `KeyError` downstream | Missing-key / unhandled boundary | No (0 of 755 relationships in this bundle target one of these 12 objects) | New code handles defensively (skip + `WARNING` evidence entry) instead of crashing; zero result change confirmed for current data |
| D-6 | `Estimate_*.py.txt` reference functions/`data1` never imported in the same file | Missing import | Yes, as originally written the scripts cannot run standalone | Not a scientific defect — reproducibility only. Fixed via proper imports in the refactor. |

Full detail, original vs. corrected values, and reasoning for each: see
`docs/LEGACY_BEHAVIOUR.md` and `docs/METHODOLOGY_DECISIONS.md`.

## 14. Duplicated code

`Estimate_malware.py.txt`, `Estimate_intrusion_set.py.txt`, and
`Estimate_courseOfaction.py.txt` are ~90-line near-verbatim copies of each
other, differing only in the `obj1['type']` filter, the output field name
(`mitigates` vs `uses`), and the output filename. Consolidated into
`risk/assessor.py::assess_entity` / `assess_entity_type` (§6 of the
restructuring brief), parameterised by entity type — no scientific change.

## 15. Scientific assumptions (undocumented in the original repository)

* The `data1` bucket values and their technique membership (severity
  ground truth) have no cited source or derivation method.
* The choice of thresholds 120/80/40/10 (severity, impact) and
  60/40/20/2 (frequency) and 11/7/3/1 (likelihood) and 20/35/50/60
  (timeliness, in weeks) are not explained anywhere.
* The choice to weight entity-level frequency as
  `external_references * (mean(technique_frequency) + 1)` (rather than a
  simple sum or average) is not explained.
* The choice to average only *non-zero* base scores in `average()` (rather
  than treating unscored techniques as 0-valued contributions) is not
  explained — it has a real effect: entities whose techniques mostly fall
  outside `data1` get a higher `impact_score` than a naive mean would give,
  because the zero-scored techniques are excluded from the denominator
  rather than dragging the average down.

Where provenance is genuinely unknown, `docs/METHODOLOGY.md` says exactly
that rather than inventing a citation.

## 16. Undocumented thresholds

See §15 — all numeric thresholds are undocumented in the original
repository. They are preserved exactly and externalised into
`configs/scoring.yaml` / `configs/risk_matrix.yaml` for auditability,
without altering their values.

## 17. Malformed identifiers

`T0381`, `T08362` — see §5/D-2.

## 18. Boundary behaviour

See §8/D-3 (timeliness) and §10/D-4 (impact level); `find_severity`,
`find_frequency`, and `find_likelihood` were individually checked and use
a consistent `>=` lower-bound convention with no gaps or overlaps — no
defect found in those three.

## 19. Reproducibility limitations

1. The original scripts do not run standalone (§2, D-6).
2. `timeliness`/`likelihood`/`risk_level` depend on `time.time()` at
   execution — re-running the legacy scripts today reproduces different
   numbers than `legacy/original_results/*.json` (which were generated at
   some unknown earlier date). The refactor introduces an explicit,
   injectable `as_of` timestamp (defaulting to "now") so a run can be
   pinned and reproduced exactly — this is an additive reproducibility
   feature, not a change to the formula itself. See
   `docs/REPRODUCIBILITY.md`.
3. No `requirements.txt`/environment pin existed; no Python version was
   specified.
4. No run metadata (input hash, config hash, git commit) was ever recorded
   alongside `Results/*.json`, so the exact inputs that produced the
   checked-in legacy results cannot be independently re-verified beyond
   the file's content itself.

## old_file → current_role → proposed_new_module

| Old file | Current role | New module |
|---|---|---|
| `Code/find_severity.py.txt` | severity lookup + `data1` table | `src/am_assurance/risk/severity.py` (+ table externalised to `configs/scoring.yaml`) |
| `Code/find_frequency.py.txt` | frequency level classifier | `src/am_assurance/risk/frequency.py` |
| `Code/find_likelihood.py.txt` | likelihood level classifier | `src/am_assurance/risk/likelihood.py` |
| `Code/find_timeliness.py.txt` | timeliness level classifier | `src/am_assurance/risk/timeliness.py` |
| `Code/Impact_level.py.txt` | impact level classifier | `src/am_assurance/risk/impact.py` |
| `Code/risk_severity.py.txt` | final qualitative risk matrix | `src/am_assurance/risk/risk_matrix.py` |
| `Code/average.py.txt` | non-zero mean aggregation | `src/am_assurance/risk/aggregation.py` |
| `Code/Estimate_malware.py.txt` | malware end-to-end script | `src/am_assurance/risk/assessor.py::assess_entity_type("malware")` |
| `Code/Estimate_intrusion_set.py.txt` | intrusion-set end-to-end script | `src/am_assurance/risk/assessor.py::assess_entity_type("intrusion-set")` |
| `Code/Estimate_courseOfaction.py.txt` | course-of-action end-to-end script | `src/am_assurance/risk/assessor.py::assess_entity_type("course-of-action")` |
| `ics-attack.json` (root) | STIX input | `data/raw/ics-attack.json` |
| `Results/*.json` | pipeline output | `legacy/original_results/*.json` (kept as regression oracle) + `results/assessments/*.json` (new runs) |
| `campaign/`, `course-of-action/`, `identity/`, `intrusion-set/`, `malware/`, `marking-definition/`, `x-mitre-data-source/` (loose per-object folders) | unused raw extract | `data/raw/stix_objects/` (archival, still unused by the pipeline) |

This audit was completed and reviewed before any scoring code was written,
per the required working order.
