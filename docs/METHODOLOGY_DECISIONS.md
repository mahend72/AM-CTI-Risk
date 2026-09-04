# Methodology Decisions

Every entry follows the required five-step process: record original
behaviour, identify the defect, determine the safest interpretation,
document the decision, add a regression test, and report whether results
changed. Cross-references: `docs/LEGACY_BEHAVIOUR.md` (raw behaviour),
`docs/CURRENT_IMPLEMENTATION_AUDIT.md` §13 (summary table).

---

## D-1: Duplicate keys in `data1` collapse bucket 34's original set

**Original behaviour**: `legacy/original_code/find_severity.py.txt`'s dict
literal silently discards `34: {"T0800","T0857","T0839","T0862"}` in favour
of the later `34: {"T08362","T0889","T0879"}`. See `LEGACY_BEHAVIOUR.md` §1.

**Defect category**: duplicate Python dictionary key (explicitly listed as
an example defect in the restructuring brief).

**Safest interpretation of intended original logic**: unknowable with
certainty — nothing in the repository states whether the first or second
`34` entry was the "intended" one, or whether the duplication was itself
accidental (e.g. from copy-pasting a table row). Guessing which was
intended would be inventing scientific data, which is explicitly
forbidden by the restructuring brief.

**Decision**: preserve the *actual runtime behaviour* exactly — i.e. the
13-key deduplicated table is the canonical severity table going forward,
externalised verbatim into `configs/scoring.yaml`. This is not a "fix"; it
is making the table that the code has always actually executed against
explicit and auditable, instead of leaving it to an accidental Python
dict-literal collision that a future editor could easily "clean up"
without realising it changes results.

**Regression test**: `tests/regression/test_severity_table_matches_legacy.py`
asserts the loaded `configs/scoring.yaml` table has exactly 13 keys with
the exact membership listed in `LEGACY_BEHAVIOUR.md` §1, and
`tests/unit/test_severity.py` asserts `severity("T0800")`,
`severity("T0862")` etc. match the values implied by the *deduplicated*
table (not the pre-collapse one).

**Did results change?** No. `configs/scoring.yaml` encodes exactly what
`data1` evaluates to at runtime today; every `base_score`/`severity` value
in `legacy/original_results/*.json` was already computed against this
collapsed table.

---

## D-2: Malformed technique IDs `T0381`, `T08362`

**Original behaviour**: both strings are present in `data1` (bucket 104
and bucket 34 respectively) but match no real technique ID in the bundle.
See `LEGACY_BEHAVIOUR.md` §2.

**Defect category**: malformed ATT&CK ID.

**Safest interpretation**: could plausibly be typos for `T0831` (already
present in bucket 104 and bucket 62) or `T0836` (already its own bucket
101), but there is no documentation confirming either guess, and both
"corrections" would change which techniques bucket 104/34 apply to —
i.e. would change scientific output for real techniques. This is exactly
the kind of silent behavioural change the brief prohibits.

**Decision**: preserve both strings exactly as-is in `configs/scoring.yaml`.
They remain permanently inert (never match a real technique) unless a
future MITRE ATT&CK revision happens to introduce an ID matching one of
these strings, which the validation layer would then flag. Both are
surfaced as `ERROR`-severity findings in
`results/validation/data_validation_report.json` with
`suggested_action: "confirm with original author whether this is a typo
for T0831/T0836/other; do not auto-correct"`.

**Regression test**:
`tests/unit/test_severity.py::test_malformed_ids_never_match_real_technique`
asserts `severity(tid)` for every one of the 79 real technique IDs in the
bundle is unaffected by the presence of `T0381`/`T08362` in the table
(i.e. removing them from the table would not change any real technique's
score — proving they are truly inert), and
`tests/unit/test_validation.py` asserts both are reported.

**Did results change?** No.

---

## D-3: `find_timeliness` boundary overlap at `like == 60`

**Original behaviour**: `like == 60` resolves to timeliness level 0 (not
1) because of statement order — see `LEGACY_BEHAVIOUR.md` §3.

**Defect category**: unhandled/ambiguous boundary (does not crash; produces
a well-defined but statement-order-dependent result).

**Safest interpretation**: the boundary constraint in the brief
("unless there is an obvious implementation defect that prevents the
documented original logic from being executed") does not apply here — the
code executes and produces a deterministic value. This is exactly the
category the brief says to leave alone unless it prevents execution.

**Decision**: preserve exactly. `risk/timeliness.py` implements the same
five independent conditionals in the same order, so `like == 60`
continues to resolve to level 0.

**Regression test**:
`tests/unit/test_timeliness.py::test_boundary_60_resolves_to_zero` pins
`timeliness_level(60.0) == 0`; boundary tests also cover 20, 35, 50 at
`-epsilon`/exact/`+epsilon`.

**Did results change?** No (this test exists to lock the behaviour down,
not to change it).

---

## D-4: `impact_level` undefined at `max_val` in `{10, 50, 80}` — CORRECTED

**Original behaviour**: `impact_level(10)`, `impact_level(50)`,
`impact_level(80)` raise `UnboundLocalError` in the legacy code as written
— see `LEGACY_BEHAVIOUR.md` §4.

**Defect category**: unhandled boundary (explicitly listed as an example
defect in the restructuring brief, and explicitly prohibited by acceptance
criterion §17: "No valid value should produce ... UnboundLocalError ...
unless that is explicitly intended and documented").

**Safest interpretation of intended original logic**: `impact_level` uses
the *identical four cut-points* (120, 80, 40/50 boundary family, 10) as
`find_severity`, which classifies its own `avg` value over the same
120/80/40/10 cut-points using **consistent `>=` lower bounds** with no
gaps (`avg>=120`, `40<=avg<120`... actually `80<=avg<120`, `40<=avg<80`,
`10<=avg<40`, `avg<10` — a clean partition, independently verified to have
no boundary defect; see `CURRENT_IMPLEMENTATION_AUDIT.md` §18). Both
functions exist in the same small codebase, were evidently written by the
same author in the same style, and both bucket a score into 5 levels using
the same numbers. The most defensible, minimal, and narrowly-scoped
correction is to make `impact_level`'s bracket boundaries closed on the
lower end (`>=`) exactly like `find_severity` already is — turning
`>80`/`>50`/`>10` into `>=80`/`>=50`/`>=10` — rather than inventing any new
threshold values, reordering the branches, or changing which label
attaches to which level.

Corrected rule:

| impact_score | level | label |
|---|---|---|
| `>= 120` | 4 | Very Critical |
| `[80, 120)` | 3 | Critical |
| `[50, 80)` | 2 | Hazardous |
| `[10, 50)` | 1 | Certain Hazard |
| `< 10` | 0 | Not Hazard |

**Decision**: apply this correction in `risk/impact.py`. This is the one
and only place in the restructured codebase where a formula's boundary
operator differs from the literal legacy source.

**Regression test**:
`tests/unit/test_impact.py::test_boundary_values_do_not_raise` calls
`impact_level(10.0)`, `impact_level(50.0)`, `impact_level(80.0)` and
asserts each returns a defined `(level, label)` instead of raising;
`tests/regression/test_legacy_comparison.py` recomputes `impact_level` for
every `impact_score` value actually present across the 93 entities in
`legacy/original_results/*.json` and asserts the corrected function
returns the identical level/label the legacy `Results/*.json` files
already contain, for every one of them (since none sit on the affected
boundaries, per `LEGACY_BEHAVIOUR.md` §4, all 93 must match unchanged).

**Did results change?** **No.** Verified: none of the 93 pre-existing
entities in `legacy/original_results/{COA,intrusion_set,malware}.json` has
an `impact_score` of exactly 10, 50, or 80 (full distinct-value lists in
`CURRENT_IMPLEMENTATION_AUDIT.md` §10), so the corrected boundary operator
is never exercised by any existing result. The correction only changes
behaviour for inputs that previously crashed.

---

## D-5: Missing-key `KeyError` risk from attack-patterns without a `mitre-attack` reference

**Original behaviour**: would raise `KeyError: 'base_score'` in
`Estimate_*.py.txt` if any scored entity related (via any relationship) to
one of the 12 `attack-pattern` objects lacking a `mitre-attack` external
reference. See `LEGACY_BEHAVIOUR.md` §5.

**Defect category**: missing-key / unhandled boundary.

**Safest interpretation**: the original author's evident intent (from the
`for ref2 ... break` structure) was to populate `technique_code`,
`base_score`, `severity`, `frequency` on every `mit` record; the absence
of an `else` clause producing a fallback value looks like an oversight,
not an intentional "treat as evidence-free" design (contrast with
`find_severity`'s explicit `if len(keys)==0: severity=0`, which *is* an
intentional documented fallback for a different missing-data case).

**Decision**: in the new `risk/assessor.py`, when a related attack-pattern
lacks a `mitre-attack` external reference, the relationship is **not**
silently dropped and does **not** crash the run — it is recorded as an
`Evidence` entry with `technique_code = None`, `base_score = None`,
`severity = None`, and a `WARNING` is attached to the entity's assurance
record explaining the gap. It is excluded from the severity/frequency
aggregation (consistent with `find_severity`'s own "unscored technique"
convention), which is the closest defensible reading of the original
aggregation intent without inventing a score for an unidentified
technique.

**Regression test**:
`tests/unit/test_assessor.py::test_missing_technique_reference_does_not_crash`
constructs a synthetic bundle with a relationship pointing to an
attack-pattern lacking a `mitre-attack` reference and asserts the assessor
completes with a `WARNING` instead of raising; `tests/regression/` confirms
0 of the 93 real entities are affected by this code path today (all their
related techniques have `mitre-attack` references).

**Did results change?** No — this code path is never exercised by the
current `data/raw/ics-attack.json` (0 of 755 relationships target one of
the 12 affected attack-patterns).

---

## D-6: Non-importable legacy scripts

**Original behaviour**: `Estimate_*.py.txt` cannot execute standalone
(undefined names). See `LEGACY_BEHAVIOUR.md` §6.

**Defect category**: missing import (reproducibility, not scientific).

**Decision**: `risk/assessor.py` properly imports `severity`, `frequency`,
`likelihood`, `timeliness`, `impact`, `risk_matrix`, `aggregation` as
modules. No formula changes.

**Did results change?** No — there is no "before" numeric behaviour to
compare against; the scripts never produced output on their own.

---

## Summary

Of six documented defects, **one** (D-4) required an actual code change,
and it is proven — by construction (only fires exactly at `max_val` in
`{10, 50, 80}`) and by exhaustive comparison against all 93 pre-existing
results — to change **zero** existing outputs. D-5 hardens a real crash
risk that likewise affects zero existing outputs. D-1, D-2, D-3, D-6 are
preserved/documented without any code-behaviour change.

**Answer to the required final question: did the restructuring change the
original risk methodology? No**, except for the single documented,
zero-impact boundary correction in D-4.
