# Phase 3.3 — Random Forest Baseline Results

Train rows: 17885 | Test rows: 4472 (stratified 80/20 split, random_state=42)

## Metrics (test set)

| Metric | Value |
|---|---|
| accuracy | 0.9682 |
| precision | 0.9727 |
| recall | 0.9412 |
| f1 | 0.9567 |
| roc_auc | 0.9907 |

## Confusion Matrix

Rows = actual, Columns = predicted. Order: [legit (0), phishing (1)]

```
[[2762   44]
 [  98 1568]]
```

## Classification Report

```
              precision    recall  f1-score   support

   legit (0)       0.97      0.98      0.97      2806
phishing (1)       0.97      0.94      0.96      1666

    accuracy                           0.97      4472
   macro avg       0.97      0.96      0.97      4472
weighted avg       0.97      0.97      0.97      4472

```

## Top 15 Features by Importance

| Feature | Importance |
|---|---|
| entropy | 0.1532 |
| url_length | 0.1458 |
| has_https | 0.0905 |
| path_length | 0.0839 |
| subdomain_depth | 0.0835 |
| aggregate_lexical_risk_score | 0.0717 |
| dot_count | 0.0694 |
| hyphen_count | 0.0577 |
| tld_freq | 0.0483 |
| digit_count | 0.0287 |
| tld_risk_score | 0.0239 |
| whois_domain_age_days | 0.0117 |
| dns_has_mx | 0.0102 |
| brand_typosquat_hit_count | 0.0095 |
| category_freq | 0.0082 |
