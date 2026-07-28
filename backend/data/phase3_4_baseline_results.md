# Phase 3.4 — XGBoost Baseline Results (Step 1: no tuning)

Test set size: n=800

| Metric | Value |
|---|---|
| accuracy | 0.9775 |
| precision | 0.9728 |
| recall | 0.9825 |
| f1 | 0.9776 |
| roc_auc | 0.9985 |

Confusion matrix: `[[389, 11], [7, 393]]`

## Top 10 features by importance

| Feature | Importance |
|---|---|
| has_https | 0.201 |
| entropy | 0.143 |
| hyphen_count | 0.084 |
| whois_recently_registered | 0.070 |
| tld_known | 0.063 |
| dot_count | 0.047 |
| ssl_issuer_amazon | 0.044 |
| url_length | 0.033 |
| digit_count | 0.032 |
| whois_domain_age_days | 0.032 |

## Comparison vs Phase 3.3 RF baseline

| Metric | RF (3.3) | XGBoost (3.4 step 1) | Delta |
|---|---|---|---|
| accuracy | 0.9712 | 0.9775 | +0.0063 |
| precision | 0.9821 | 0.9728 | -0.0093 |
| recall | 0.9600 | 0.9825 | +0.0225 |
| f1 | 0.9709 | 0.9776 | +0.0067 |
| roc_auc | 0.9980 | 0.9985 | +0.0005 |