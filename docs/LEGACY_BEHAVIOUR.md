# Legacy Behaviour Register

This document records, verbatim, the *actual observed runtime behaviour* of
the original code for every case where that behaviour is not obvious from
reading the source — duplicate keys, malformed data, and boundary
overlaps. Each entry is independently verified by executing the relevant
fragment. See `docs/METHODOLOGY_DECISIONS.md` for what was done about each
one (in every case: preserved, unless marked corrected with evidence of
zero result change).

## §1 — Duplicate dictionary keys in `data1` (`find_severity.py.txt`)

The literal dict in `Code/find_severity.py.txt` contains the key `34`
twice and the key `10` three times:

```python
data1 = {
  ...
  34: {"T0800", "T0857", "T0839", "T0862"},        # written first
  ...
  10: {},
  10: {},
  10: {"T0813"},                                    # written last
  34: {"T08362", "T0889", "T0879"},                 # written last
}
```

Python dict *literals* silently keep only the last assignment to a
repeated key. The actual dict that exists at runtime, verified by
evaluating the literal exactly as written:

| key | as-written (first occurrence) | **actual runtime value** |
|---|---|---|
| `10` | `{}` | `{"T0813"}` (no data lost — first two were empty) |
| `34` | `{"T0800", "T0857", "T0839", "T0862"}` | `{"T08362", "T0879", "T0889"}` (**original 4-item set fully discarded**) |

Full runtime `data1` (13 keys, matching `legacy/original_code/find_severity.py.txt` evaluated exactly as written):

```
10  -> {T0813}
24  -> {T0837}
34  -> {T08362, T0879, T0889}
41  -> {}
62  -> {T0816, T0831, T0847, T0858, T0879}
68  -> {T0800, T0839, T0857, T0862, T0881}
87  -> {T0806, T0809, T0811, T0867, T0874, T0882, T0885, T0887}
101 -> {T0836}
104 -> {T0381, T0804, T0813, T0831, T0838, T0856}
105 -> {T0800, T0816, T0830, T0839, T0840, T0857, T0867, T0873, T0885, T0887}
115 -> {T0800, T0816, T0830, T0839, T0840, T0857, T0867, T0873, T0885, T0887}
130 -> {T0806, T0830, T0839, T0851, T0856, T0889}
141 -> {T0801, T0835, T0842, T0856, T0877}
```

**Practical effect on scores**: `T0800`, `T0857`, `T0839`, `T0862` no
longer have bucket `34` among their matches (T0800/T0857/T0839 still match
via buckets 105/115/130/68 as applicable; `T0862` still matches via bucket
68). Because `find_severity` averages *all* matching bucket keys, dropping
bucket 34 from these techniques' match sets changes their computed
`base_score` from what a naive reading of the source (with both `34`
entries additive) would suggest — but this is exactly what the code
*actually does and always did*, including in every value stored in
`legacy/original_results/*.json`. This is the behaviour preserved by the
refactor.

Disposition: `docs/METHODOLOGY_DECISIONS.md` D-1 — preserved exactly.

## §2 — Malformed technique identifiers in `data1`

`"T0381"` (bucket 104) and `"T08362"` (bucket 34, itself only present due
to the duplicate-key collapse in §1) do not match the ID format of any
real MITRE ATT&CK for ICS technique. Verified: **zero** of the 79 distinct
`mitre-attack` technique IDs actually present in
`data/raw/ics-attack.json` equal either string.

**Practical effect**: `find_severity` performs exact-string set membership
(`item in value`); neither string can ever be looked up because no real
technique ID equals `"T0381"` or `"T08362"`. Both entries are inert dead
weight in the table — they do not silently corrupt any other technique's
score, and removing them would not change any output either. They are
left in place unchanged.

Disposition: `docs/METHODOLOGY_DECISIONS.md` D-2 — preserved exactly,
flagged as an `ERROR`-severity finding in
`results/validation/data_validation_report.json` for visibility.

## §3 — `find_timeliness` boundary overlap at `like == 60`

```python
if like <=20: severity = 4
if like <=35 and like >20: severity = 3
if like <=50 and like >35: severity = 2
if like <=60 and like >50: severity = 1
if like >=60: severity = 0
```

These are five independent `if` statements, not an `if/elif` chain. At
`like == 60` exactly, the fourth statement (`<=60 and >50`) is `True`
*and* the fifth (`>=60`) is `True`. Because both execute in sequence and
each unconditionally overwrites `severity`, the fifth statement's
assignment wins. **Verified**: `find_timeliness(60) == 0`, not `1`.

All other boundary points (20, 35, 50) are unambiguous — only one branch
matches — verified by direct execution at each cut point and at
`cut ± 1e-9`.

Disposition: `docs/METHODOLOGY_DECISIONS.md` D-3 — preserved exactly
(`like == 60` continues to resolve to level 0).

## §4 — `impact_level` undefined at `max_val` in `{10, 50, 80}`

```python
if max_val >=120: ...          # level 4
if max_val <120 and max_val >80: ...   # level 3
if max_val <80 and max_val >50: ...    # level 2
if max_val <50 and max_val >10: ...    # level 1
if max_val < 10: ...                    # level 0
```

At `max_val == 80`: branch 2 requires `>80` (False), branch 3 requires
`<80` (False) — neither matches. Same gap at `max_val == 50` and
`max_val == 10`. **Verified by direct execution**:
`impact_level(80)`, `impact_level(50)`, and `impact_level(10)` each raise
`UnboundLocalError: local variable 'level_0' referenced before assignment`
in the legacy code, exactly as written.

**Verified against all 93 existing entities** in
`legacy/original_results/{COA,intrusion_set,malware}.json`: no entity's
stored `impact_score` equals `10`, `50`, `80`, or `120` (full distinct
value lists are in `docs/CURRENT_IMPLEMENTATION_AUDIT.md` §10). This
defect has never fired against the data that produced the checked-in
legacy results.

Disposition: `docs/METHODOLOGY_DECISIONS.md` D-4 — **corrected** (only
defect in this register that changes code behaviour, and only at the three
exact boundary points; verified to change zero of the 93 existing
results).

## §5 — Missing `mitre-attack` reference on 12 `attack-pattern` objects

12 of 91 `attack-pattern` objects in the bundle have no `mitre-attack`
external reference (e.g. `attack-pattern--e0d74479-...` "Modify Control
Logic"). In the legacy nested-loop code, if a `relationship` pointed from a
scored entity to one of these 12 objects, `mitigations.append(mit)` would
still execute (it sits after, not inside, the `for ref2 in
external_references` loop), appending a `mit` dict **missing**
`technique_code`, `base_score`, `severity`, and `frequency`. The subsequent
list-comprehension `[obj['base_score'] for obj in mitigations]` would then
raise `KeyError: 'base_score'`.

**Verified**: 0 of the 755 `relationship` objects in the bundle have
`relationship_type in {mitigates, uses}` (or any type) with
`source_ref` equal to a scored entity's id **and** `target_ref` equal to
one of these 12 objects. This defect is real but latent — it has never
fired against this dataset.

Disposition: `docs/METHODOLOGY_DECISIONS.md` D-5 — new code handles this
defensively (skips the relationship, records a `WARNING` in evidence)
rather than crashing; verified to change zero of the 93 existing results
because it never triggers.

## §6 — Non-standalone scripts

`Code/Estimate_{malware,intrusion_set,courseOfaction}.py.txt` reference
`find_severity`, `average`, `impact_level`, `find_timeliness`,
`find_frequency`, `find_likelihood`, `risk_severity`, and `data1` without
importing them. As saved (`.py.txt`, not `.py`), and without manually
concatenating all ten files into one namespace first, none of the three
scripts can execute. This is not a scientific defect (no formula is
affected) — it is a packaging/reproducibility defect, corrected by the
refactor's proper module imports.
