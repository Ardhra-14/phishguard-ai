# Phase 3.2 — Training Dataset Audit

Source: `data/training_dataset.csv`  
Shape: **4000 rows x 44 columns**

## 1. Null report (all columns, sorted by null %)

|                              | dtype   |   null_count |   null_pct |
|:-----------------------------|:--------|-------------:|-----------:|
| dom_credential_form_detected | float64 |         4000 |     100    |
| visual_similarity_score      | float64 |         4000 |     100    |
| whois_registrar              | object  |         2448 |      61.2  |
| whois_domain_age_days        | float64 |         2397 |      59.92 |
| ssl_days_until_expiry        | float64 |         1326 |      33.15 |
| ssl_issuer                   | object  |         1326 |      33.15 |
| ssl_expired                  | object  |         1152 |      28.8  |
| url                          | object  |            0 |       0    |
| dns_has_aaaa                 | int64   |            0 |       0    |
| idn_confusable_count         | int64   |            0 |       0    |
| idn_risk_score               | float64 |            0 |       0    |
| idn_punycode_flag            | int64   |            0 |       0    |
| dns_resolves                 | bool    |            0 |       0    |
| dns_a_record_count           | int64   |            0 |       0    |
| whois_recently_registered    | int64   |            0 |       0    |
| dns_has_mx                   | int64   |            0 |       0    |
| domain                       | object  |            0 |       0    |
| whois_privacy_protected      | int64   |            0 |       0    |
| whois_found                  | int64   |            0 |       0    |
| ssl_valid                    | bool    |            0 |       0    |
| ssl_self_signed              | int64   |            0 |       0    |
| idn_is_homograph             | int64   |            0 |       0    |
| tld_known                    | int64   |            0 |       0    |
| tld_risk_score               | float64 |            0 |       0    |
| is_ip_address                | int64   |            0 |       0    |
| label                        | int64   |            0 |       0    |
| url_length                   | int64   |            0 |       0    |
| hyphen_count                 | int64   |            0 |       0    |
| dot_count                    | int64   |            0 |       0    |
| digit_count                  | int64   |            0 |       0    |
| entropy                      | float64 |            0 |       0    |
| subdomain_depth              | int64   |            0 |       0    |
| has_https                    | int64   |            0 |       0    |
| has_at_symbol                | int64   |            0 |       0    |
| tld                          | object  |            0 |       0    |
| path_length                  | int64   |            0 |       0    |
| query_param_count            | int64   |            0 |       0    |
| special_char_count           | int64   |            0 |       0    |
| brand_impersonation_score    | float64 |            0 |       0    |
| brand_matched_count          | int64   |            0 |       0    |
| brand_keyword_hit_count      | int64   |            0 |       0    |
| brand_typosquat_hit_count    | int64   |            0 |       0    |
| brand_has_action_word        | int64   |            0 |       0    |
| aggregate_lexical_risk_score | float64 |            0 |       0    |

## 2. Phase 4 stub columns (expected 100% null)

- `visual_similarity_score`: OK — 100% null as expected
- `dom_credential_form_detected`: OK — 100% null as expected

## 3. Lookup-derived columns with genuine (non-stub) missingness

These are the columns where missingness reflects real lookup failures (NXDOMAIN, no cert, WHOIS timeout, etc.) rather than an unbuilt feature. Per the handoff, this missingness may itself be signal and is a candidate for a `_was_missing` companion boolean rather than silent imputation.

|                       | dtype   |   null_count |   null_pct |
|:----------------------|:--------|-------------:|-----------:|
| whois_registrar       | object  |         2448 |      61.2  |
| whois_domain_age_days | float64 |         2397 |      59.92 |
| ssl_days_until_expiry | float64 |         1326 |      33.15 |
| ssl_issuer            | object  |         1326 |      33.15 |
| ssl_expired           | object  |         1152 |      28.8  |

## 4. Categorical cardinality (encoding strategy inputs)

### `tld`

- Unique values (excluding null): **204**
- Non-null rows: 4000 / 4000
- Top 10 values cover: **76.88%** of non-null rows

| value | count | pct of non-null |
|---|---|---|
| com | 1366 | 34.15% |
| dev | 819 | 20.47% |
| app | 285 | 7.12% |
| io | 157 | 3.92% |
| net | 149 | 3.72% |
| ru | 81 | 2.02% |
| org | 79 | 1.98% |
| cc | 56 | 1.4% |
| de | 46 | 1.15% |
| cn | 37 | 0.92% |

### `whois_registrar`

- Unique values (excluding null): **259**
- Non-null rows: 1552 / 4000
- Top 10 values cover: **49.81%** of non-null rows

| value | count | pct of non-null |
|---|---|---|
| GoDaddy.com, LLC | 210 | 13.53% |
| NameCheap, Inc. | 119 | 7.67% |
| MarkMonitor, Inc. | 118 | 7.6% |
| Amazon Registrar, Inc. | 85 | 5.48% |
| TUCOWS.COM, CO. | 46 | 2.96% |
| RU-CENTER-RU | 42 | 2.71% |
| GANDI SAS | 41 | 2.64% |
| Network Solutions, LLC | 39 | 2.51% |
| Cloudflare, Inc. | 38 | 2.45% |
| Gname.com Pte. Ltd. | 35 | 2.26% |

### `ssl_issuer`

- Unique values (excluding null): **42**
- Non-null rows: 2674 / 4000
- Top 10 values cover: **97.38%** of non-null rows

| value | count | pct of non-null |
|---|---|---|
| Google Trust Services | 1326 | 49.59% |
| Let's Encrypt | 668 | 24.98% |
| DigiCert Inc | 216 | 8.08% |
| Amazon | 157 | 5.87% |
| GlobalSign nv-sa | 88 | 3.29% |
| Sectigo Limited | 82 | 3.07% |
| GoDaddy.com, Inc. | 21 | 0.79% |
| GoDaddy.com | 20 | 0.75% |
| DigiCert, Inc. | 17 | 0.64% |
| Hellenic Academic and Research Institutions CA | 9 | 0.34% |

## 5. Numeric column summary

|                              |   count |     mean |      std |     min |      25% |      50% |      75% |       max |
|:-----------------------------|--------:|---------:|---------:|--------:|---------:|---------:|---------:|----------:|
| label                        |    4000 |    0.5   |    0.5   |   0     |    0     |    0.5   |    1     |     1     |
| url_length                   |    4000 |   39.022 |   27.964 |  13     |   24     |   33     |   47     |  1072     |
| hyphen_count                 |    4000 |    1.028 |    1.591 |   0     |    0     |    0     |    2     |     9     |
| dot_count                    |    4000 |    1.744 |    0.638 |   1     |    1     |    2     |    2     |     8     |
| digit_count                  |    4000 |    1.12  |    2.259 |   0     |    0     |    0     |    2     |    28     |
| entropy                      |    4000 |    3.547 |    0.566 |   1.88  |    3.122 |    3.466 |    3.958 |     4.897 |
| subdomain_depth              |    4000 |    0.744 |    0.638 |   0     |    0     |    1     |    1     |     7     |
| has_https                    |    4000 |    0.732 |    0.443 |   0     |    0     |    1     |    1     |     1     |
| is_ip_address                |    4000 |    0     |    0     |   0     |    0     |    0     |    0     |     0     |
| has_at_symbol                |    4000 |    0.001 |    0.035 |   0     |    0     |    0     |    0     |     1     |
| path_length                  |    4000 |    7.46  |   11.964 |   0     |    1     |    1     |   11     |   132     |
| query_param_count            |    4000 |    0.06  |    0.397 |   0     |    0     |    0     |    0     |    16     |
| special_char_count           |    4000 |    0.169 |    1.135 |   0     |    0     |    0     |    0     |    36     |
| brand_impersonation_score    |    4000 |    0.024 |    0.062 |   0     |    0     |    0     |    0     |     0.583 |
| brand_matched_count          |    4000 |    0.242 |    0.584 |   0     |    0     |    0     |    0     |     5     |
| brand_keyword_hit_count      |    4000 |    0.003 |    0.057 |   0     |    0     |    0     |    0     |     1     |
| brand_typosquat_hit_count    |    4000 |    0.25  |    0.638 |   0     |    0     |    0     |    0     |     7     |
| brand_has_action_word        |    4000 |    0.022 |    0.147 |   0     |    0     |    0     |    0     |     1     |
| tld_risk_score               |    4000 |    0.347 |    0.188 |   0.01  |    0.15  |    0.35  |    0.5   |     0.94  |
| tld_known                    |    4000 |    0.57  |    0.495 |   0     |    0     |    1     |    1     |     1     |
| idn_is_homograph             |    4000 |    0.001 |    0.032 |   0     |    0     |    0     |    0     |     1     |
| idn_confusable_count         |    4000 |    0     |    0     |   0     |    0     |    0     |    0     |     0     |
| idn_risk_score               |    4000 |    0.001 |    0.019 |   0     |    0     |    0     |    0     |     0.6   |
| idn_punycode_flag            |    4000 |    0.001 |    0.032 |   0     |    0     |    0     |    0     |     1     |
| dns_a_record_count           |    4000 |    1.623 |    1.797 |   0     |    1     |    2     |    2     |    40     |
| dns_has_aaaa                 |    4000 |    0.428 |    0.495 |   0     |    0     |    0     |    1     |     1     |
| dns_has_mx                   |    4000 |    0.2   |    0.4   |   0     |    0     |    0     |    0     |     1     |
| whois_domain_age_days        |    1603 | 5592.81  | 3966.78  |   0     | 1954.5   | 5233     | 9291.5   | 15182     |
| whois_recently_registered    |    4000 |    0.016 |    0.125 |   0     |    0     |    0     |    0     |     1     |
| whois_privacy_protected      |    4000 |    0.076 |    0.265 |   0     |    0     |    0     |    0     |     1     |
| whois_found                  |    4000 |    0.413 |    0.492 |   0     |    0     |    0     |    1     |     1     |
| ssl_self_signed              |    4000 |    0     |    0     |   0     |    0     |    0     |    0     |     0     |
| ssl_days_until_expiry        |    2674 |   84.022 |   46.259 |   2     |   55     |   80     |   85     |   260     |
| visual_similarity_score      |       0 |  nan     |  nan     | nan     |  nan     |  nan     |  nan     |   nan     |
| dom_credential_form_detected |       0 |  nan     |  nan     | nan     |  nan     |  nan     |  nan     |   nan     |
| aggregate_lexical_risk_score |    4000 |    0.185 |    0.067 |   0.056 |    0.116 |    0.207 |    0.237 |     0.459 |

## 6. Suspicious value checks

- Label distribution: {1: 2000, 0: 2000} (expected 2000/2000 per handoff).
- **13** duplicate `url` values found (handoff claims dedup during collection — worth confirming).
