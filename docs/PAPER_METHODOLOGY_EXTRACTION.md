# Paper Methodology Extraction

Source: paper text pasted into this conversation (prose body only — see
`docs/MISSING_METHODOLOGY_INPUTS.md` for what did not survive the copy:
all 9 equations' formulas and 12 of 14 tables' numeric contents). This
document records, element by element, exactly what the paper states,
distinguishing **directly quoted/stated facts** from **inferred structure**
and from **BLOCKED (not available)** items. Nothing below is invented.

Format: **Paper element → what is known → planned code module.**

---

## 1. The seven threat categories (§4.1) — fully available

Directly stated, with the paper's own rationale for each:

| # | Category | Paper's description (condensed) |
|---|---|---|
| 1 | Manufactured Object | The printed object itself — material substitution, surface alteration, biological contamination. |
| 2 | Manufacturing Equipment | 3D printers/software/control parameters (cf. Stuxnet, Aurora); ageing/maintenance risk. |
| 3 | Environment | Physical area, temperature/humidity, contamination, explosion/implosion, fire, NBC. |
| 4 | Intellectual Property | CAD/STL files, toolpath, machine access — data theft, sabotage, financial loss. |
| 5 | Body Injuries and Diseases | End-user/operator health — defective design, poor maintenance, ultrafine particle exposure. |
| 6 | Human Capital | Ineffective training, insufficient management support, poor communication. |
| 7 | Financial Risk | Inflation, FX fluctuation, insufficient financing. |

Source: "inspired by Yampolskiy et al.'s study on compromised elements and
manipulations with crucial enhancements from Cabezali et al.'s
categorization" (§4.1) — attribution preserved, not re-derived.

**Code module**: `data/reference/am_threats.csv` (category column) +
`src/am_cti_risk/core/models.py` (an enum or constrained field, not a
free-text string, so an invalid category is rejected at load time).

---

## 2. The five threat characteristics (§4.2) — definitions available, numeric mapping BLOCKED

| Characteristic | Paper's definition |
|---|---|
| Targeting Precision | "likelihood of achieving the intended goal" |
| Area of Impact | "potential extent of an attack's influence" |
| Collateral Damage | "unexpected harm to the supply chain or individuals" |
| Stealth | "ability of an attack to avoid detection" |
| Attack Repeatability | "attacker's capability to repeat an attack" |

Each is rated on the same 5-point ordinal scale: **Unknown, Low, Medium,
High, Critical**.

Table 1 ("Threat Impact level parameter values") is supposed to assign a
numeric value to each of these 5 levels. The paper states: *"Each
characteristic has corresponding values (0, 1, 10, 50) assigned to the
severity levels (Unknown, Low, Medium, High, Critical)."* This is 4
numbers for 5 levels — **BLOCKED**, see `MISSING_METHODOLOGY_INPUTS.md`.
Do not assume Unknown=0, Low=1, Medium=10, High=?, Critical=50 without
confirmation; the gap could equally mean a transcription drop of a 5th
number, or that two adjacent levels intentionally share a value in the
real table.

**Code module**: `src/am_cti_risk/impact/characteristics.py` (structure
only, ready to accept the mapping once Table 1 is confirmed) +
`configs/impact.yaml` (the mapping itself, once known).

---

## 3. The 22 AM threats with qualitative characteristics (§4.3) — best-effort extraction

**Confidence: high for the per-threat qualitative levels** (each is stated
explicitly in prose, one paragraph per threat, e.g. *"high severity level
regarding targeting precision... impact is critical... Collateral damage
is expected to be critical... exhibits medium stealth... Attack
repeatability is critical"*). **Confidence: medium for the category
assignment per threat** — the paper does not label each of the 22 threats
with its category inline in §4.3; the category was inferred from (a) the
threat's subject matter matching one of the 7 category definitions in
§4.1, and (b) the threats being presented in an order that groups cleanly
into contiguous category blocks (1–2, 3–6, 7–9, 10–13, 14–16, 17–19,
20–22). This inference should be verified against the actual Table 2 /
Figure 3 if they become available — it is not a verbatim reading of a
table cell.

**This is not a substitute for Table 2.** It is a transcription of the
paper's own descriptive paragraphs, which is the closest approximation
possible without the table itself.

| # | Threat name | Category (inferred) | Targeting Precision | Area of Impact | Collateral Damage | Stealth | Attack Repeatability |
|---|---|---|---|---|---|---|---|
| 1 | Altering physical properties of object | Manufactured Object | High | Critical | Critical | Medium | Critical |
| 2 | NBC contamination to object | Manufactured Object | Low | High | High | Low | High |
| 3 | Alteration in electronic circuit | Manufacturing Equipment | High | High | Low | High | High |
| 4 | Ageing or outdated 3D equipment | Manufacturing Equipment | Medium | Low | Low | Medium | Medium |
| 5 | Irreparable damage threat to 3D equipment | Manufacturing Equipment | Medium | Low | Low | Medium | Medium |
| 6 | Explosion/Implosion to 3D equipment | Manufacturing Equipment | Medium | Medium | Medium | Low | Low |
| 7 | Explosion/Implosion to the environment | Environment | Low | Medium | Medium | Low | Low |
| 8 | Fire threat to the environment | Environment | Low | Medium | Medium | Low | Medium |
| 9 | NBC contamination to the environment | Environment | Low | Medium | Medium | Medium | Medium |
| 10 | Unauthorised access to CAD model phase | Intellectual Property | High | High | High | Medium | Medium |
| 11 | Unauthorised access to STL file | Intellectual Property | High | Low | Low | Medium | Low |
| 12 | Unauthorised access to toolpath | Intellectual Property | High | Medium | Low | Low | Low |
| 13 | Unauthorised access to physical machine | Intellectual Property | High | Low | Medium | Medium | Low |
| 14 | Defective design | Body Injuries and Diseases | Medium | Critical | High | Medium | High |
| 15 | Defects during the manufacturing process | Body Injuries and Diseases | High | Critical | Critical | Medium | High |
| 16 | Exposure to ultrafine particles | Body Injuries and Diseases | High | High | Low | Low | Low |
| 17 | Ineffective training plan | Human Capital | High | Medium | Low | Low | Low |
| 18 | Insufficient management support | Human Capital | High | Low | Medium | Medium | Low |
| 19 | Poor communication | Human Capital | Medium | Critical | High | High | Low |
| 20 | Inflation threat | Financial Risk | Medium | High | Low | Low | Low |
| 21 | Foreign exchange rate fluctuation | Financial Risk | High | Low | Medium | Medium | Low |
| 22 | Insufficient financing | Financial Risk | High | High | Critical | Medium | Low |

These 22 rows, in this exact form, populate
`data/reference/am_threats.csv`. Numeric severity columns are intentionally
omitted from that file until Table 1's mapping is confirmed (see §2 above)
— populating them now would mean guessing.

**Code module**: `data/reference/am_threats.csv` (data) +
`src/am_cti_risk/core/models.py::AMThreat` / `ThreatCharacteristics`
(typed representation) + `src/am_cti_risk/cti/mappings.py` (loader).

---

## 4. Threat impact decay (§4.4, Equation 1, Table 4) — concept known, formula and constants BLOCKED

Concept (directly stated): impact of an IOC decays over time; decay
function `f(x)` depends on active time `x` and a rate parameter referred
to as `λ` (and possibly a second parameter `a`/`b` — the prose mentions
"parameters *a* and *b*" without clarifying whether these are the same as
`λ`, one of them, or additional). `f(x) → 0` as `x` grows.

Category-dependent rate: `λ` differs for {critical, high} IOCs vs
{medium} IOCs vs {all other} IOCs (3 distinct λ values, not given
numerically). Critical IOCs stay "active" up to 21 days (this is the
point where `f(x)` reaches 0 for that category). One class described as
"a significant IOC" holds full value for ~5 days before decay begins —
which category "significant" refers to is not disambiguated in the
supplied text.

**BLOCKED**: the functional form of Equation 1, the numeric λ values in
Table 4, and the full lifespan schedule for every severity category (only
the Critical row's 21-day endpoint and one ambiguous ~5-day figure
survive).

**Code module**: `src/am_cti_risk/impact/decay.py::calculate_decay(...)`
— structure/signature can be drafted now (pure function, explicit
parameters, per your requirement in item 13), but the body cannot be
implemented correctly without the real equation and Table 4 values. A
placeholder that raises `NotImplementedError` referencing this document
is the honest option, not a guessed exponential/linear curve.

---

## 5. Impact aggregation and overall impact (§4.5, Equations 2 & 3, Table 5) — concept known, weights/thresholds BLOCKED

Equation 2 (concept): `I_i = w1*T + w2*A + w3*C + w4*S + w5*R` (aggregate
impact score for IOC `i`, from the 5 characteristic severity scores,
each independently weighted). Stated: "we set weights as [w2 and w3
higher]... considering that area of impact and collateral damage may lead
to more severe consequences" — **the actual w1..w5 numbers are not
present** in the supplied text (the sentence describing them is
truncated/the values were likely in an equation image).

Equation 3 (concept): overall impact = (T+A+C+S+R, each "scaled by a
factor of 10") × decay rate (from Eq. 1/2's λ, a).

**Inconsistency flagged** (see also `METHODOLOGY_DECISIONS.md`): Eq. 3's
"each scaled by a factor of 10" does not obviously reconcile with Table
1's "(0, 1, 10, 50)" characteristic value set — if T/A/C/S/R already come
from a {0,1,10,50}-like set (per Table 1), multiplying by 10 again would
produce values up to 500, inconsistent with Table 5's implied impact-level
range (unknown, but the paper elsewhere discusses impact scores in a
range that appears bounded well below 500, judging by the 0-100 occurrence
scale used elsewhere for a comparable quantity). This cannot be resolved
without the actual Eq. 2/3 text and Table 5.

Table 5 (impact-level classification thresholds): **BLOCKED**, no data.

**Code module**: `src/am_cti_risk/impact/aggregation.py::calculate_aggregate_impact(...)`
and `src/am_cti_risk/impact/classifier.py::classify_impact(...)` —
signatures can be drafted (named parameters, not `a,b,c,d,e`, per your
requirement in item 14), bodies blocked.

---

## 6. Likelihood (§5, Equations 4 & 5) — concept known, weights/formula BLOCKED

Concept: `Likelihood = f(Reliability, Severity, Occurrence)`, parameterised
by weights `w1, w2, w3` (Eq. 4); under "equal importance" (`w1=w2=w3`),
this simplifies to Eq. 5. Neither equation's literal form survived.

**Code module**: `src/am_cti_risk/likelihood/aggregation.py`.

---

## 7. Source reliability (§5.1, Equation 6, Table 6) — weights known, formula and thresholds partially BLOCKED

**Recovered concrete values**: weights `w_extensiveness = 0.8`,
`w_timeliness = 1.0`, `w_completeness = 0.8` — directly stated: *"The
weights (0.8, 1.0, 0.8) for extensiveness (E), timeliness (Ti), and
completeness (Co)..."*. The paper's stated rationale: these reflect
"impact on physical, security, and financial aspects, reflecting
severity."

Sub-metric definitions (concept-level, formula symbols described in words
but not shown as rendered equations):

* **Extensiveness** = (number of filled-in optional IOC properties) /
  (maximum number of contextual properties) — a ratio in [0, 1] by
  construction. The specific defining variables (`f_s`, `M` in the prose)
  are named but the literal equation glyph is not present — the ratio
  described is unambiguous enough to be low-risk to implement as
  `filled_optional_properties / max_contextual_properties`, but this
  should still be verified against the actual equation.
* **Timeliness** = a function of `t0` (timestamp the fastest source
  sighted an IOC) and `t_s` (timestamp this source sighted it), divided
  in some way related to `n` (number of IOCs shared by the source).
  **BLOCKED**: the exact combination (e.g. `t0/t_s`, `1 - (t_s-t0)/n`, or
  something else) is not recoverable from prose alone — several different
  formulas would all match the verbal description.
* **Completeness** = (total IOCs shared by source `s`) / (total distinct
  IOCs across all sources) — a ratio in [0, 1], directly analogous to
  extensiveness in form.

Table 6 (source trust level thresholds, mapping the relevance score `R_s`
to a qualitative trust level): **BLOCKED**, no data.

Equation 6 itself (the weighted-average combination of E, Ti, Co into
`R_s`, including whether it normalises by `Σw = 2.6` or by 3): **BLOCKED**
in its literal form, though a weighted arithmetic mean is the natural
reading of "weighted average" as stated in prose.

**Code module**: `src/am_cti_risk/likelihood/extensiveness.py`,
`timeliness.py`, `completeness.py`, `reliability.py`.

---

## 8. IOC / threat severity (§5.2, Equation 7, Table 7) — concept known, mapping BLOCKED

Concept: for IOC type `i`, average the severity scores assigned by every
data source that reports on it (Equation 7 — simple mean is implied by
"average severity score," literal formula not shown). Table 7 maps
qualitative severity (low → critical, per prose) to a numeric score:
**BLOCKED**, no data.

**Code module**: `src/am_cti_risk/likelihood/severity.py`.

---

## 9. Occurrence / frequency (§5.3, Equation 8, Tables 8 & 9) — concept and scale known, thresholds BLOCKED

Concept: average, across all data sources, how many times IOC type `i` has
been observed (Equation 8 — again a mean, literal formula not shown).
Recovered: the resulting occurrence score `O_i` is on a **0–100 scale**
(directly stated). Tables 8 and 9 (occurrence-value and impact-level-value
lookup bands within that 0–100 scale): **BLOCKED**, no cut points
available. Table 9's caption in the supplied text duplicates the "impact
level value" wording used for Tables 1/3/5 — flagged as a probable
scraping/caption artifact in `METHODOLOGY_DECISIONS.md`, not resolved
here.

**Code module**: `src/am_cti_risk/likelihood/occurrence.py`.

---

## 10. Risk estimation and the risk matrix (§6, Equation 9, Table 10) — BLOCKED, this is the critical gap

Concept: `Risk = f(Likelihood, Impact)`, then classified into **Unknown,
Low, Moderate, High, Critical** via a risk matrix (Table 10), described
as covering all combinations of impact level and likelihood/threat
severity.

**Nothing about Equation 9's literal form or a single cell of Table 10 is
present in the supplied text.** This is the single most consequential
blocked item — `src/am_cti_risk/risk/matrix.py` and `calculator.py`
cannot be written with real values until this table is supplied.

**Code module**: `src/am_cti_risk/risk/calculator.py`,
`src/am_cti_risk/risk/matrix.py`.

---

## 11. Threat ranking (§7.1, Table 12) — rule known, full result table BLOCKED

Rule (directly stated, §7.1's "Risk" discussion): rank primarily by risk
level; when two threats share a risk level, use threat impact score as
the tiebreaker (higher impact ranks first).

Partial validation data recovered from prose (not exact scores, ordinal
only):

* Ranks 1–4 (highest risk), in order: "Physical property danger to 3D
  object" (i.e. threat #1, Altering physical properties of object),
  "BI&D threat owing to poor design" (≈ threat #14, Defective design, or
  possibly #15 — the paper's short-hand name does not disambiguate
  cleanly between #14 and #15, both under Body Injuries and Diseases),
  "CS&IP risk in CAD model phase" (≈ threat #10, Unauthorised access to
  CAD model phase), "NBC threat to 3D object" (= threat #2, NBC
  contamination to object).
* Named as low-risk-level: "Fire threat to the environment" (#8),
  "E/I threat to the environment" (#7), "E/I threat to 3D equipment"
  (#6), "Reduced lifespan threat to 3D equipment" (likely #4, Ageing/
  outdated equipment — name not an exact match, flagged), "Irreparable
  damage threat to 3D equipment" (#5).

This is usable only as a **coarse plausibility check** once the full
engine exists (e.g. "does our #1-ranked threat come out as
Altering-physical-properties, and do these five come out low?") — it is
explicitly **not** sufficient for exact-value regression testing, which
requires Table 12's real numbers.

**Code module**: `src/am_cti_risk/risk/ranking.py`.

---

## 12. CVE validation (§7.2–7.3, Tables 13 & 14) — methodology known, results BLOCKED

Methodology (directly stated): MITRE/NVD CVE dataset, 1084 MB, 249,816
CVEs (1999 to 2023-03-21), CVSS scores 0–10. For this experiment
specifically, reliability was fixed at 0.8 for all sources (not a general
threshold — an experiment-specific simplification, see
`MISSING_METHODOLOGY_INPUTS.md` recovered-values list). Frequency was
computed from dataset metadata; IOC severity was derived from each CVE's
CVSS score. **The exact mapping from CVSS score to the framework's
severity/impact/likelihood scale is not given.**

Findings (qualitative, directly stated): code-injection CVEs
(CVE-2021-21480, CVE-2009-4046, CVE-2009-4037, CVE-2018-20187,
CVE-2018-19436) rated "critical or high-risk"; unauthorised-access CVEs
(CVE-2021-2238, CVE-2018-13804, CVE-2017-9630, CVE-2022-20817,
CVE-2019-13945) rated "high or medium risk." No numeric CVSS/impact/
likelihood/risk values are given for any of them (Table 14 itself is
blocked).

**Important distinction preserved** (per your instruction): CVSS score is
raw *source vulnerability severity evidence* feeding into the framework's
`severity`/`occurrence` inputs — it is never reported as the framework's
own risk output. `cve_validation.py` must keep these separate fields.

**Code module**: `src/am_cti_risk/cti/cve_loader.py`,
`src/am_cti_risk/validation/cve_validation.py`.

---

## Summary table: paper element → status

| Element | Status |
|---|---|
| 7 categories | Available |
| 22 threats, qualitative characteristics | Available (best-effort transcription from prose; category-per-threat is inferred, not table-verbatim) |
| Table 1 (characteristic numeric values) | BLOCKED (partial: 4 of the intended 5 numbers given, unassigned) |
| Equation 1 + Table 4 (decay) | BLOCKED (concept + 2 partial data points only) |
| Equations 2 & 3 + Table 5 (impact aggregation/classification) | BLOCKED (weights and thresholds missing; one internal inconsistency flagged) |
| Equations 4 & 5 (likelihood) | BLOCKED (formula missing) |
| Equation 6 + Table 6 (reliability) | BLOCKED formula/thresholds; weights (0.8/1.0/0.8) recovered |
| Equation 7 + Table 7 (severity) | BLOCKED |
| Equation 8 + Tables 8/9 (occurrence) | BLOCKED thresholds; 0–100 scale recovered |
| Equation 9 + Table 10 (risk matrix) | BLOCKED — critical |
| Table 11 (impact/likelihood results) | BLOCKED as numbers; a few qualitative claims recovered |
| Table 12 (risk score/rank) | BLOCKED as numbers; top-4 order + 5 low-risk names recovered |
| Table 13 (CVE dataset) | Available |
| Table 14 (CVE validation results) | BLOCKED as numbers; example CVE IDs by category recovered |

See `docs/MISSING_METHODOLOGY_INPUTS.md` for the itemised blocking list
and what would resolve each one.
