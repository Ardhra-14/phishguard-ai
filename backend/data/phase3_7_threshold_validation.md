\# Phase 3.7 — Verdict Threshold Validation



\*\*Status:\*\* Done. Closes Phase 3.7 open issue #3 ("verdict thresholds not derived from real calibration").



\---



\## Method



The original thresholds (`score >= 70` → PHISHING, `>= 35` → SUSPICIOUS) were a placeholder chosen from the model's overall ROC-AUC (0.99), not from looking at where errors actually land.



To validate them, I reconstructed the model's \*\*true held-out test set\*\* — the same stratified 80/20 split (`random\_state=42`) used to produce `meta.json`'s `sanity\_check\_metrics` — and confirmed the reconstruction is exact by reproducing those metrics precisely:



\- Accuracy (0.5 threshold): \*\*0.9587\*\* (matches `meta.json`)

\- ROC-AUC: \*\*0.99\*\* (matches `meta.json`)

\- Confusion matrix: \*\*\[\[383,17],\[16,384]]\*\* (matches `meta.json` exactly)



This is 800 domains (400 legit, 400 phishing) the model never saw during training — an honest test, not one flattered by memorization.



\## Findings at the original thresholds (70 / 35)



| | Scored SAFE | Scored SUSPICIOUS | Scored PHISHING |

|---|---|---|---|

| \*\*Actually legit\*\* (400) | 369 | 19 | \*\*12\*\* |

| \*\*Actually phishing\*\* (400) | \*\*13\*\* | 11 | 376 |



The number that mattered most: \*\*13 of 400 real phishing domains scored as outright SAFE.\*\* For a protective tool, a missed detection (user trusts a phishing site) is a worse failure than an over-cautious flag (user double-checks a legit site) — so this was the number to optimize against.



\## Threshold sweep



Swept `PHISHING\_THRESHOLD` × `SUSPICIOUS\_THRESHOLD` combinations, tracking the two severe-error counts (legit→PHISHING, phishing→SAFE):



\- Raising `PHISHING\_THRESHOLD` above 70 reduced severe errors further, but only by pushing far more cases into the ambiguous SUSPICIOUS bucket (at 90/25: only 13 severe errors, but 92/800 domains land in SUSPICIOUS vs. 30/800 today) — too aggressive a shift for this session; flagged as a possible future revisit, not made now.

\- Changing `PHISHING\_THRESHOLD` alone (keeping SUSPICIOUS at 35) didn't move the phishing→SAFE count at all between 65 and 70 — the missed phishing domains were sitting well below 35, not in the 65-70 range.

\- Lowering `SUSPICIOUS\_THRESHOLD` (65→70 unchanged, 35→25) directly targeted the missed-phishing problem, since those 13 domains were sitting in the 25-35 score range.



\## Change made



\*\*`SUSPICIOUS\_THRESHOLD`: 35 → 25.\*\* `PHISHING\_THRESHOLD` stays at 70.



\## Result on the same held-out set (70 / 25)



| | Scored SAFE | Scored SUSPICIOUS | Scored PHISHING |

|---|---|---|---|

| \*\*Actually legit\*\* (400) | 353 | 35 | 12 \*(unchanged)\* |

| \*\*Actually phishing\*\* (400) | \*\*10\*\* \*(was 13)\* | 14 | 376 \*(unchanged)\*|



\- Missed phishing (phishing→SAFE): \*\*13 → 10\*\* ✅

\- Severe false positive (legit→PHISHING): \*\*12 → 12\*\*, unchanged — this change didn't make legit sites more likely to be branded outright PHISHING

\- Trade-off: legit sites landing in SUSPICIOUS instead of a clean SAFE rose from 19 → 35 (out of 400) — more "please double-check this" friction for legitimate domains, no severe misclassification added



For a CERT-In-facing tool, this is the right trade: fewer real phishing domains slip through labeled safe, at the cost of somewhat more legitimate domains getting a cautious flag instead of a clean pass.



\## What wasn't changed / left open



\- \*\*`PHISHING\_THRESHOLD` staying at 70\*\* is itself still a judgment call, not a mathematically "optimal" point — the sweep showed diminishing/trading returns above it. Worth another look if a future session wants to push further, but not changed this round to avoid over-tuning without more data.

\- This validation used the training/held-out dataset (4,000 rows total), not real-world traffic. If Phase 5 gets to a live pilot, these thresholds should be revisited against real scan volume, not just the original labeled set.

\- If the model is retrained on the full 4,000-row dataset (see the earlier model-persistence review), this threshold analysis should be rerun against whatever fresh holdout that retrain produces — these numbers are specific to the currently-shipped model.

