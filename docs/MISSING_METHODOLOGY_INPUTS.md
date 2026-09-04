# Missing Methodology Inputs

Status: **BLOCKING.** This document is written first, ahead of
`PAPER_METHODOLOGY_EXTRACTION.md`, because its content determines how much
of that document can be filled in versus marked unavailable.

The text supplied in this conversation is the paper's prose body. Every
table is present only as a caption followed by a "Full size table"
placeholder (no cell contents), and every equation is present only as a
bare reference number — `(1)` through `(9)` — with no mathematical
expression. This is consistent with copying a rendered HTML journal page:
inline tables are collapsible widgets and equations are images/MathML,
neither of which survive a plain-text copy. Prose paragraphs came through
completely; the quantitative apparatus did not.

Per your instruction, nothing below is inferred or guessed. Each item is
marked **BLOCKED** and the implementation of the corresponding code module
cannot start until it is resolved.

## Equations — ALL 9 are blocked (structure known from prose, no formula)

| Eq. | What the prose says exists | What is missing |
|---|---|---|
| (1) | Decay function `f(x)` with parameters (described as related to `a`, `b`/`λ`), `x` = active time; f(x) → 0 as x increases; `λ` sets decay rate. | The actual functional form (e.g. is it exponential, linear, piecewise?) and the meaning/values of every parameter symbol. |
| (2) | Aggregate impact score `I_i` = weighted sum of 5 characteristic severity scores (T, A, C, S, R) with weights `w1..w5`. Prose states "we set weights as [...]" for w2 (area of impact) and w3 (collateral damage) being higher — **the actual numeric weight values are missing** (the sentence is cut off in the source; no numbers follow "we set weights as"). |
| (3) | Overall impact = (T+A+C+S+R, "each scaled by a factor of 10") × decay rate from Eq. 1/2. | Exact formula; also an unresolved inconsistency with Table 1 (see below). |
| (4) | Likelihood = weighted combination of reliability `R`, severity `Sev`, occurrence `O`, with weights `w1,w2,w3`. | Exact formula (sum? weighted average?). |
| (5) | Equation 4 simplified under "equal importance" (`w1=w2=w3`). | Exact simplified formula. |
| (6) | Source relevance score = weighted average of extensiveness/timeliness/completeness. Weights **are** given in prose: `w_extensiveness=0.8, w_timeliness=1.0, w_completeness=0.8` (see "recovered values" below). | The exact aggregation formula (weighted arithmetic mean is the natural reading, but the literal equation is not present to confirm normalisation, e.g. whether it divides by `Σw` or by 3). |
| (7) | Average IOC severity score across data sources for IOC type `i`. | Exact formula (simple mean is implied but not shown). |
| (8) | Average IOC occurrence/frequency across data sources for IOC type `i`. | Exact formula. |
| (9) | Risk = function of Likelihood and Impact. | Exact formula — is it a matrix lookup only (per Table 10), a product, a weighted sum feeding into the matrix, or something else? |

## Tables — 12 of 14 are blocked; 1 is partially usable; 1 fully unusable as a table

| Table | Caption / topic (from prose) | Status |
|---|---|---|
| 1 | "Threat Impact level parameter values" — characteristic severity → numeric value mapping | **BLOCKED (partial).** Prose gives "(0, 1, 10, 50)" for 5 levels (Unknown, Low, Medium, High, Critical) — 4 numbers for 5 levels. Cannot confidently assign which number maps to which level, and one value is simply absent. See inconsistency note below. |
| 2 | Qualitative per-threat characteristic assignment for all 22 threats | **Not directly available as a table**, but see `PAPER_METHODOLOGY_EXTRACTION.md` — §4.3's prose describes each threat's 5 characteristics in words for all 22 threats, and that has been transcribed as a best-effort structured extraction. This is **not the same as reading the actual table cells** and should be verified against Table 2 directly if it becomes available. |
| 3 | "Threat Impact level parameter values" (same caption text as Table 1 in the supplied text — likely a scraping duplication artifact; prose says Table 3 actually holds "interpretation values") | **BLOCKED.** No data, and the duplicate caption itself is a red flag needing the source PDF to resolve. |
| 4 | IOC lifespan / decay-rate (`λ`) values per severity category | **BLOCKED (partial).** Prose confirms categories share λ values by group ("critical and high IOCs" one λ, "medium IOCs" another, "all other IOCs" a third) and that critical IOCs are active up to 21 days, with "a significant IOC" (category unclear — High? Critical?) holding value for ~5 days before decay starts. No numeric λ values themselves. |
| 5 | Impact-level classification thresholds (aggregate score → Unknown/Low/Medium/High/Critical) | **BLOCKED.** No data. |
| 6 | Source trust level thresholds | **BLOCKED.** No data. |
| 7 | IOC severity score mapping | **BLOCKED.** No data. |
| 8 | Occurrence value estimation (prose confirms scale is 0–100) | **BLOCKED (partial).** Scale range known; cut points unknown. |
| 9 | Impact level value estimation (via occurrence — caption text again duplicates the "impact level" wording used for Tables 1/3/5, another possible scraping artifact) | **BLOCKED.** No data, caption ambiguity noted. |
| 10 | **The risk matrix** (Impact level × Likelihood level → Risk level) | **BLOCKED — critical.** This is the single most important missing table; without it, `risk/matrix.py` cannot be written at all, not even as a stub with real values. |
| 11 | Aggregated threat impact and likelihood levels (per-threat results) | **BLOCKED** as exact numbers. Some qualitative claims survive in prose (e.g. "Physical property danger to 3D object," "NBC threat to 3D object," "CS&IP risk in CAD model phase" called out as high-impact/high-likelihood) — usable only as a coarse sanity check, not a regression oracle. |
| 12 | Risk score, level, and rank per threat | **BLOCKED** as exact numbers. Prose gives the **rank order of the top 4** and names 5 threats confirmed as "low-risk level" — see extraction doc. Not sufficient for exact-value regression tests, only ordinal sanity checks. |
| 13 | CVE dataset details | **BLOCKED** as a table, but prose gives concrete facts: 1084MB, 249,816 CVEs, 1999–2023-03-21, CVSS 0–10 scale, source = MITRE/NVD. |
| 14 | Top CVEs with CVE score / impact level / likelihood / risk level | **BLOCKED** as exact numbers. Prose names specific CVE IDs by category (code injection: CVE-2021-21480, CVE-2009-4046, CVE-2009-4037, CVE-2018-20187, CVE-2018-19436 — called "critical or high-risk"; unauthorised access: CVE-2021-2238, CVE-2018-13804, CVE-2017-9630, CVE-2022-20817, CVE-2019-13945 — called "high or medium risk"). No CVSS/impact/likelihood/risk numeric values for any of them. |

## Recovered concrete numeric values (the only ones present anywhere in the supplied text)

These are the **only** numbers in the entire paper text that are unambiguous
and directly usable:

1. Source reliability weights (§5.1): `w_extensiveness = 0.8`,
   `w_timeliness = 1.0`, `w_completeness = 0.8`.
2. CVE-validation experiment setting (§7.2): a fixed reliability/trust
   score of `0.8` was used for all data sources in that specific
   experiment (not a general framework threshold).
3. Occurrence score scale: 0–100 (§5.3), no cut points.
4. Decay timing facts (§4.4, qualitative): critical IOCs remain active up
   to 21 days; one class of IOC (referred to as "a significant IOC" —
   ambiguous whether this means "High" or "Critical") holds full value for
   ~5 days before decay begins.
5. CVE dataset facts (§7.2): 1084 MB, 249,816 CVEs, 1999–2023-03-21 (NVD
   CVSS 0–10 scale).

Everything else quantitative in the paper — all 9 equations in full, and
the cell contents of Tables 1, 3, 4 (λ values), 5, 6, 7, 8, 9, 10, 11, 12,
14 — is **not present** in the text supplied and must not be guessed.

## What would unblock this

Any of the following would resolve most or all of the above:

* The original PDF (PDFs of journal articles almost always render
  equations and tables as extractable text/vector content, unlike the
  HTML "Full size table" widget view this text appears to have come
  from) — I can read it directly with the PDF-reading tool if you give
  me a file path.
* A DOI or direct URL to the article, which I can attempt to fetch.
* Manually pasting or photographing specifically: Tables 1, 3, 4, 5, 6, 7,
  8, 9, 10 in full, and the 9 equations as rendered (screenshots are fine
  — I can read images).

## Recommended path forward given this gap

Given that the risk matrix (Table 10) and every scoring equation are
blocked, `docs/METHODOLOGY_DECISIONS.md`-style "implement now" work on
`src/am_cti_risk/` cannot begin for the quantitative engine. What I can
safely do without the missing data:

* Finish the qualitative extraction (7 categories, 22 threats, 5
  characteristics per threat, from prose) into
  `data/reference/am_threats.csv` — labels only, numeric severity-score
  columns left blank/flagged pending Table 1.
* Scaffold the repository/module structure with clear `NotImplementedError`
  stubs referencing this document, so the shape is ready the moment the
  real tables/equations arrive.
* Preserve the existing prototype code untouched under
  `legacy/original_prototype/` for provenance, as instructed.

I have not done the scaffolding yet — see my report in this turn for why
I'm holding on code until you've seen this list.
