# Phase 3.3 — Random Forest Baseline Results

Train rows: 3878 | Test rows: 970 (stratified 80/20 split, random_state=42)

## Metrics (test set)

| Metric | Value |
|---|---|
| accuracy | 0.9680 |
| precision | 0.9848 |
| recall | 0.9498 |
| f1 | 0.9670 |
| roc_auc | 0.9922 |

## Confusion Matrix

Rows = actual, Columns = predicted. Order: [legit (0), phishing (1)]

```
[[485   7]
 [ 24 454]]
```

## Classification Report

```
              precision    recall  f1-score   support

   legit (0)       0.95      0.99      0.97       492
phishing (1)       0.98      0.95      0.97       478

    accuracy                           0.97       970
   macro avg       0.97      0.97      0.97       970
weighted avg       0.97      0.97      0.97       970

```

## Top 15 Features by Importance

| Feature | Importance |
|---|---|
| url_length | 0.1359 |
| entropy | 0.1277 |
| aggregate_lexical_risk_score | 0.0713 |
| has_https | 0.0659 |
| path_length | 0.0632 |
| whois_domain_age_days | 0.0624 |
| subdomain_depth | 0.0518 |
| dot_count | 0.0514 |
| tld_freq | 0.0407 |
| hyphen_count | 0.0407 |
| dns_has_mx | 0.0357 |
| tld_risk_score | 0.0222 |
| whois_registrar_freq | 0.0175 |
| digit_count | 0.0174 |
| ssl_days_until_expiry | 0.0165 |
