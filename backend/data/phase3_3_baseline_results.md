# Phase 3.3 — Random Forest Baseline Results

Train rows: 3200 | Test rows: 800 (stratified 80/20 split, random_state=42)

## Metrics (test set)

| Metric | Value |
|---|---|
| accuracy | 0.9537 |
| precision | 0.9504 |
| recall | 0.9575 |
| f1 | 0.9539 |
| roc_auc | 0.9888 |

## Confusion Matrix

Rows = actual, Columns = predicted. Order: [legit (0), phishing (1)]

```
[[380  20]
 [ 17 383]]
```

## Classification Report

```
              precision    recall  f1-score   support

   legit (0)       0.96      0.95      0.95       400
phishing (1)       0.95      0.96      0.95       400

    accuracy                           0.95       800
   macro avg       0.95      0.95      0.95       800
weighted avg       0.95      0.95      0.95       800

```

## Top 15 Features by Importance

| Feature | Importance |
|---|---|
| url_length | 0.1430 |
| entropy | 0.1313 |
| whois_domain_age_days | 0.0934 |
| has_https | 0.0764 |
| aggregate_lexical_risk_score | 0.0600 |
| subdomain_depth | 0.0551 |
| path_length | 0.0542 |
| dot_count | 0.0488 |
| hyphen_count | 0.0351 |
| ssl_days_until_expiry | 0.0309 |
| tld_freq | 0.0277 |
| whois_found | 0.0245 |
| whois_registrar_freq | 0.0229 |
| whois_domain_age_days_was_missing | 0.0210 |
| digit_count | 0.0205 |
