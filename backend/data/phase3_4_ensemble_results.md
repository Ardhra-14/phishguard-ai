# Phase 3.4 — RF + XGBoost Soft-Voting Ensemble Results

## Four-way comparison (held-out test set, n=800)

| Metric | RF (3.3) | XGB untuned (3.4-1) | XGB tuned (3.4-3) | Ensemble (3.4-5) |
|---|---|---|---|---|
| accuracy | 0.9712 | 0.9775 | 0.9800 | 0.9800 |
| precision | 0.9821 | 0.9728 | 0.9824 | 0.9824 |
| recall | 0.9600 | 0.9825 | 0.9775 | 0.9775 |
| f1 | 0.9709 | 0.9776 | 0.9799 | 0.9799 |
| roc_auc | 0.9980 | 0.9985 | 0.9982 | 0.9984 |

Confusion matrix (ensemble): `[[393, 7], [9, 391]]`

**Best F1 of the four: Ensemble (0.9799)**

Decision rule per handoff: only adopt the ensemble for Phase 3.6 if it meaningfully beats the better of RF/tuned-XGB alone. A tie or marginal gain on an 800-row test set is not meaningful -- prefer the simpler single model (tuned XGBoost) in that case.
