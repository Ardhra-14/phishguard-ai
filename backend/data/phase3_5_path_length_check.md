# Phase 3.5 — path_length SHAP sanity check

Context: path_length ranked #4 by mean |SHAP| (0.841) in the global SHAP
results, but does not appear in tuned XGBoost's native top-10
feature_importances_ from Phase 3.4. path_length was the exact feature
responsible for the Phase 3.1 leak (zero variance in legit class,
1.0000 across every metric). This check verifies whether the current
SHAP/native disagreement is a leftover artifact or a legitimate signal.

## Summary stats (test set, n=800)

| | legit (label=0) | phishing (label=1) |
|---|---|---|
| n | 400 | 400 |
| mean path_length | 6.09 | 9.57 |
| std path_length | 6.32 | 22.57 |
| unique-value fraction | 0.045 | 0.122 |
| mean SHAP contribution | -0.9056 | 0.9050 |

## Jump detector

Largest single-step change in SHAP value as path_length increases across the
sorted test set: 3.6202 (64.2% of the total SHAP
range for this feature), occurring near path_length=0.

**Read this as:** a smooth/gradual trend (jump fraction well under ~15-20%
concentrated at one point, no unique-value fraction near-zero on one class)
supports path_length being a genuine signal. A sharp jump concentrated at
one value, or a near-zero unique-value fraction on the legit class,
suggests the _synthesize_path() fallback is still producing a distinguishable
cluster and needs a closer look at build_training_dataset.py before trusting
this feature's ranking.

See data/phase3_5_path_length_dependence.png for the visual — color = has_https or another
correlated feature (whatever shap.dependence_plot auto-selected), which can
also hint at *why* path_length matters if it does.
