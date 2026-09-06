# Phase 3.4 — XGBoost Untuned Baseline Results (Step 1)

Plain XGBClassifier(random_state=42, n_jobs=-1), no hyperparameter search.

Held-out test set: n=800

## Two-way comparison (held-out test set)

| Metric | RF (3.3) | XGB untuned (3.4-1) | Delta |
|---|---|---|---|
| accuracy | 0.9725 | 0.9537 | -0.0188 |
| precision | 0.9773 | 0.9481 | -0.0292 |
| recall | 0.9675 | 0.9600 | -0.0075 |
| f1 | 0.9724 | 0.9540 | -0.0184 |
| roc_auc | 0.9968 | 0.9917 | -0.0051 |

Confusion matrix: `[[379, 21], [16, 384]]`

## Top 10 features by importance

| Feature | Importance |
|---|---|
| has_https | 0.253 |
| entropy | 0.145 |
| dot_count | 0.076 |
| whois_domain_age_days | 0.056 |
| url_length | 0.047 |
| dns_resolves | 0.047 |
| whois_recently_registered | 0.043 |
| digit_count | 0.034 |
| whois_found | 0.031 |
| tld_risk_score | 0.029 |
