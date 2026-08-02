# Phase 3.4 — XGBoost Tuned Results (Step 3: RandomizedSearchCV)

Search: 50 iterations, 5-fold stratified CV, scoring=roc_auc

Best CV roc_auc: 0.9933

## Best hyperparameters

```json
{
  "colsample_bytree": 0.7043574493366855,
  "gamma": 0.07652270145192375,
  "learning_rate": 0.28069652934305006,
  "max_depth": 9,
  "min_child_weight": 1,
  "n_estimators": 424,
  "reg_alpha": 1.3679275387962821,
  "reg_lambda": 2.655479075364698,
  "subsample": 0.9775566418243029
}
```

Held-out test set: n=800

## Three-way comparison (held-out test set)

| Metric | RF (3.3) | XGB untuned (3.4-1) | XGB tuned (3.4-3) | Delta vs untuned |
|---|---|---|---|---|
| accuracy | 0.9712 | 0.9775 | 0.9550 | -0.0225 |
| precision | 0.9821 | 0.9728 | 0.9550 | -0.0178 |
| recall | 0.9600 | 0.9825 | 0.9550 | -0.0275 |
| f1 | 0.9709 | 0.9776 | 0.9550 | -0.0226 |
| roc_auc | 0.9980 | 0.9985 | 0.9896 | -0.0089 |

Confusion matrix (tuned): `[[382, 18], [18, 382]]`

## Top 10 features by importance (tuned model)

| Feature | Importance |
|---|---|
| has_https | 0.247 |
| entropy | 0.123 |
| subdomain_depth | 0.083 |
| whois_domain_age_days_was_missing | 0.074 |
| url_length | 0.051 |
| whois_domain_age_days | 0.049 |
| dot_count | 0.046 |
| whois_recently_registered | 0.044 |
| ssl_issuer_amazon | 0.033 |
| tld_known | 0.025 |
