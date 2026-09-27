# Phase 3.4 — XGBoost Untuned Baseline Results (Step 1)

Plain XGBClassifier(random_state=42, n_jobs=-1), no hyperparameter search.

Held-out test set: n=4472

## Two-way comparison (held-out test set)

| Metric | RF (3.3) | XGB untuned (3.4-1) | Delta |
|---|---|---|---|
| accuracy | 0.9725 | 0.9714 | -0.0011 |
| precision | 0.9773 | 0.9753 | -0.0020 |
| recall | 0.9675 | 0.9472 | -0.0203 |
| f1 | 0.9724 | 0.9610 | -0.0114 |
| roc_auc | 0.9968 | 0.9919 | -0.0049 |

Confusion matrix: `[[2766, 40], [88, 1578]]`

## Top 10 features by importance

| Feature | Importance |
|---|---|
| has_https | 0.277 |
| entropy | 0.084 |
| dot_count | 0.072 |
| hyphen_count | 0.071 |
| is_ip_address | 0.052 |
| whois_recently_registered | 0.040 |
| url_length | 0.038 |
| path_length | 0.030 |
| digit_count | 0.025 |
| whois_registrar_was_missing | 0.022 |
