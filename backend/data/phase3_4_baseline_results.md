# Phase 3.4 — XGBoost Untuned Baseline Results (Step 1)

Plain XGBClassifier(random_state=42, n_jobs=-1), no hyperparameter search.

Held-out test set: n=970

## Two-way comparison (held-out test set)

| Metric | RF (3.3) | XGB untuned (3.4-1) | Delta |
|---|---|---|---|
| accuracy | 0.9725 | 0.9639 | -0.0086 |
| precision | 0.9773 | 0.9703 | -0.0070 |
| recall | 0.9675 | 0.9561 | -0.0114 |
| f1 | 0.9724 | 0.9631 | -0.0093 |
| roc_auc | 0.9968 | 0.9945 | -0.0023 |

Confusion matrix: `[[478, 14], [21, 457]]`

## Top 10 features by importance

| Feature | Importance |
|---|---|
| has_https | 0.231 |
| whois_recently_registered | 0.093 |
| is_ip_address | 0.081 |
| entropy | 0.078 |
| dot_count | 0.060 |
| url_length | 0.042 |
| whois_domain_age_days | 0.036 |
| digit_count | 0.030 |
| ssl_issuer_digicert_inc | 0.028 |
| ssl_expired | 0.023 |
