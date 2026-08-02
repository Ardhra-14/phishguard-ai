# Phase 3.4 — RF + XGBoost Soft-Voting Ensemble Results

## Four-way comparison (held-out test set, n=800)

| Metric | RF (3.3) | XGB untuned (3.4-1) | XGB tuned (3.4-3) | Ensemble (3.4-5) |
|---|---|---|---|---|
| accuracy | 0.9537 | 0.9538 | 0.9550 | 0.9587 |
| precision | 0.9504 | 0.9481 | 0.9550 | 0.9576 |
| recall | 0.9575 | 0.9600 | 0.9550 | 0.9600 |
| f1 | 0.9539 | 0.9540 | 0.9550 | 0.9588 |
| roc_auc | 0.9888 | 0.9917 | 0.9896 | 0.9900 |

Confusion matrix (ensemble): `[[383, 17], [16, 384]]`

**Best F1 of the four: Ensemble (0.9588)**

Decision rule per handoff: only adopt the ensemble for Phase 3.6 if it meaningfully beats the better of RF/tuned-XGB alone. A tie or marginal gain on an 800-row test set is not meaningful -- prefer the simpler single model (tuned XGBoost) in that case.
