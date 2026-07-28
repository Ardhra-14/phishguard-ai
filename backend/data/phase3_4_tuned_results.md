# Phase 3.4 — XGBoost Tuned Results (Step 3: RandomizedSearchCV)

Search: 50 iterations, 5-fold stratified CV, scoring=roc_auc

Best CV roc_auc: 0.9952

## Best hyperparameters

```json
{
  "colsample_bytree": 0.610167650697638,
  "gamma": 0.5394571349665223,
  "learning_rate": 0.019114463849152934,
  "max_depth": 8,
  "min_child_weight": 1,
  "n_estimators": 663,
  "reg_alpha": 1.1265511439527673,
  "reg_lambda": 2.9343063024914464,
  "subsample": 0.6557325817623503
}
```

Held-out test set: n=800

## Three-way comparison (held-out test set)

| Metric | RF (3.3) | XGB untuned (3.4-1) | XGB tuned (3.4-3) | Delta vs untuned |
|---|---|---|---|---|
| accuracy | 0.9712 | 0.9775 | 0.9800 | +0.0025 |
| precision | 0.9821 | 0.9728 | 0.9824 | +0.0096 |
| recall | 0.9600 | 0.9825 | 0.9775 | -0.0050 |
| f1 | 0.9709 | 0.9776 | 0.9799 | +0.0023 |
| roc_auc | 0.9980 | 0.9985 | 0.9982 | -0.0003 |

Confusion matrix (tuned): `[[393, 7], [9, 391]]`

## Top 10 features by importance (tuned model)

| Feature | Importance |
|---|---|
| has_https | 0.171 |
| entropy | 0.109 |
| hyphen_count | 0.089 |
| url_length | 0.068 |
| whois_domain_age_days | 0.041 |
| ssl_issuer_missing | 0.040 |
| ssl_issuer_godaddycom | 0.034 |
| subdomain_depth | 0.033 |
| dot_count | 0.027 |
| whois_domain_age_days_was_missing | 0.024 |
