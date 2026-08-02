# Phase 3.5 — SHAP Global Explainability Results (Ensemble)

Model: RF + XGBoost soft-voting ensemble. n_test=800, random_state=42.

Explained component-wise (TreeExplainer on each of RF and XGBoost separately) rather than as a single combined value, since the two models' raw SHAP outputs live in different spaces (RF: probability, XGBoost: margin/log-odds) and naively averaging them would be mathematically invalid. Both components contribute equally to the final soft-voted prediction.

## Top 15 features — RandomForest component (mean |SHAP|, probability space)

| Rank | Feature | Mean |SHAP| |
|---|---|---|
| 1 | url_length | 0.0812 |
| 2 | entropy | 0.0766 |
| 3 | whois_domain_age_days | 0.0648 |
| 4 | has_https | 0.0615 |
| 5 | subdomain_depth | 0.0474 |
| 6 | dot_count | 0.0428 |
| 7 | aggregate_lexical_risk_score | 0.0320 |
| 8 | path_length | 0.0252 |
| 9 | hyphen_count | 0.0217 |
| 10 | ssl_days_until_expiry | 0.0188 |
| 11 | dns_has_mx | 0.0182 |
| 12 | whois_found | 0.0174 |
| 13 | dns_a_record_count | 0.0135 |
| 14 | digit_count | 0.0129 |
| 15 | whois_domain_age_days_was_missing | 0.0117 |

## Top 15 features — XGBoost component (mean |SHAP|, margin space)

| Rank | Feature | Mean |SHAP| |
|---|---|---|
| 1 | url_length | 1.2284 |
| 2 | whois_domain_age_days | 1.0284 |
| 3 | entropy | 0.9678 |
| 4 | has_https | 0.9538 |
| 5 | path_length | 0.5694 |
| 6 | dot_count | 0.5112 |
| 7 | ssl_days_until_expiry | 0.3895 |
| 8 | dns_a_record_count | 0.3529 |
| 9 | aggregate_lexical_risk_score | 0.3362 |
| 10 | tld_freq | 0.2885 |
| 11 | dns_resolves | 0.2644 |
| 12 | subdomain_depth | 0.1900 |
| 13 | tld_risk_score | 0.1864 |
| 14 | whois_registrar_freq | 0.1834 |
| 15 | ssl_issuer_let's_encrypt | 0.1449 |

_path_length should no longer dominate either ranking after the trailing-slash normalization fix -- see phase3_5_path_length_check.md for the investigation that led here. Compare against each model's native feature_importances_ from phase3_4_baseline_results.md / phase3_4_tuned_results.md for a sanity check._
