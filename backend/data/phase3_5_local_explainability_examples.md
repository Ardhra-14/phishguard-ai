# Phase 3.5 — Local Explainability Examples

Three example rows from the held-out test set, explained via explain_single_row(). Demonstrates the function Phase 3.6 should call per scanned URL.

### Highest-confidence PHISHING prediction (true label: phishing) (predicted P(phishing) = 0.9999)

**RandomForest component** (probability space, base value 0.5007):

| Feature | Value | SHAP contribution |
|---|---|---|
| has_https | 0 | +0.1258 |
| entropy | 3.88 | +0.0873 |
| url_length | 43 | +0.0636 |
| whois_domain_age_days | -1 | +0.0467 |
| subdomain_depth | 1 | +0.0378 |
| dot_count | 2 | +0.0335 |
| aggregate_lexical_risk_score | 0.216 | +0.0213 |
| whois_found | 0 | +0.0194 |

**XGBoost component** (margin/log-odds space, base value 0.0286):

| Feature | Value | SHAP contribution |
|---|---|---|
| has_https | 0 | +2.3129 |
| url_length | 43 | +1.2811 |
| entropy | 3.88 | +0.9522 |
| whois_domain_age_days | -1 | +0.8955 |
| path_length | 0 | +0.6107 |
| dot_count | 2 | +0.4924 |
| tld_freq | 0.0803 | +0.4424 |
| aggregate_lexical_risk_score | 0.216 | +0.3388 |

### Highest-confidence LEGIT prediction (true label: legit) (predicted P(phishing) = 0.0001)

**RandomForest component** (probability space, base value 0.5007):

| Feature | Value | SHAP contribution |
|---|---|---|
| whois_domain_age_days | 9.22e+03 | -0.0694 |
| url_length | 23 | -0.0639 |
| entropy | 3.32 | -0.0460 |
| aggregate_lexical_risk_score | 0.112 | -0.0433 |
| has_https | 1 | -0.0386 |
| subdomain_depth | 0 | -0.0369 |
| dot_count | 1 | -0.0324 |
| dns_has_mx | 1 | -0.0300 |

**XGBoost component** (margin/log-odds space, base value 0.0286):

| Feature | Value | SHAP contribution |
|---|---|---|
| whois_domain_age_days | 9.22e+03 | -1.5329 |
| dns_a_record_count | 4 | -1.1849 |
| entropy | 3.32 | -1.0282 |
| url_length | 23 | -0.9540 |
| has_https | 1 | -0.5259 |
| aggregate_lexical_risk_score | 0.112 | -0.5179 |
| dot_count | 1 | -0.4091 |
| whois_registrar_freq | 0.00175 | -0.3233 |

### Boundary case (closest to 0.5) (true label: legit) (predicted P(phishing) = 0.4999)

**RandomForest component** (probability space, base value 0.5007):

| Feature | Value | SHAP contribution |
|---|---|---|
| url_length | 43 | +0.1178 |
| subdomain_depth | 0 | -0.1005 |
| whois_domain_age_days | -1 | +0.0877 |
| entropy | 3.62 | +0.0838 |
| dot_count | 1 | -0.0772 |
| has_https | 1 | -0.0298 |
| ssl_days_until_expiry | -1 | +0.0253 |
| whois_found | 0 | +0.0247 |

**XGBoost component** (margin/log-odds space, base value 0.0286):

| Feature | Value | SHAP contribution |
|---|---|---|
| url_length | 43 | +1.5318 |
| path_length | 19 | -1.3033 |
| whois_domain_age_days | -1 | +1.0669 |
| dot_count | 1 | -0.9219 |
| aggregate_lexical_risk_score | 0.117 | -0.9087 |
| subdomain_depth | 0 | -0.4778 |
| has_https | 1 | -0.3858 |
| ssl_days_until_expiry | -1 | +0.3516 |
