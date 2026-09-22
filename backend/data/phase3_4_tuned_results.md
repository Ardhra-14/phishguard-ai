# Phase 3.4 — XGBoost Tuned Results (Step 3: RandomizedSearchCV)

Search: 50 iterations, 5-fold stratified CV, scoring=roc_auc

Best CV roc_auc: 0.9931

## Best hyperparameters

```json
{
  "colsample_bytree": 0.7182534743350856,
  "gamma": 0.527471299151353,
  "learning_rate": 0.14239502544004398,
  "max_depth": 5,
  "min_child_weight": 4,
  "n_estimators": 430,
  "reg_alpha": 0.6486900420105479,
  "reg_lambda": 0.9273078414523568,
  "subsample": 0.7425191352307899
}
```

Held-out test set: n=970

## Three-way comparison (held-out test set)

| Metric | RF (3.3) | XGB untuned (3.4-1) | XGB tuned (3.4-3) | Delta vs untuned |
|---|---|---|---|---|
| accuracy | 0.9712 | 0.9775 | 0.9711 | -0.0064 |
| precision | 0.9821 | 0.9728 | 0.9747 | +0.0019 |
| recall | 0.9600 | 0.9825 | 0.9665 | -0.0160 |
| f1 | 0.9709 | 0.9776 | 0.9706 | -0.0070 |
| roc_auc | 0.9980 | 0.9985 | 0.9958 | -0.0027 |

Confusion matrix (tuned): `[[480, 12], [16, 462]]`

## Top 10 features by importance (tuned model)

| Feature | Importance |
|---|---|
| has_https | 0.146 |
| hyphen_count | 0.135 |
| dot_count | 0.086 |
| whois_recently_registered | 0.081 |
| entropy | 0.060 |
| url_length | 0.046 |
| dns_has_mx | 0.035 |
| whois_domain_age_days | 0.031 |
| subdomain_depth | 0.029 |
| digit_count | 0.028 |
