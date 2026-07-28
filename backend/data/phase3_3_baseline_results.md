# Phase 3.3 — Random Forest Baseline Results

Train rows: 3200 | Test rows: 800 (stratified 80/20 split, random_state=42)

## Metrics (test set)

| Metric | Value |
|---|---|
| accuracy | 0.9712 |
| precision | 0.9821 |
| recall | 0.9600 |
| f1 | 0.9709 |
| roc_auc | 0.9980 |

## Confusion Matrix

Rows = actual, Columns = predicted. Order: [legit (0), phishing (1)]

```
[[393   7]
 [ 16 384]]
```

## Classification Report

```
              precision    recall  f1-score   support

   legit (0)       0.96      0.98      0.97       400
phishing (1)       0.98      0.96      0.97       400

    accuracy                           0.97       800
   macro avg       0.97      0.97      0.97       800
weighted avg       0.97      0.97      0.97       800

```

## Top 15 Features by Importance

| Feature | Importance |
|---|---|
| url_length | 0.1449 |
| entropy | 0.1233 |
| has_https | 0.0963 |
| hyphen_count | 0.0735 |
| whois_domain_age_days | 0.0728 |
| aggregate_lexical_risk_score | 0.0701 |
| path_length | 0.0540 |
| subdomain_depth | 0.0491 |
| dot_count | 0.0425 |
| digit_count | 0.0372 |
| tld_freq | 0.0287 |
| whois_found | 0.0248 |
| tld_risk_score | 0.0208 |
| whois_domain_age_days_was_missing | 0.0180 |
| whois_registrar_freq | 0.0175 |
