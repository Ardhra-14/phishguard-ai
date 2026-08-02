# Phase 3.2 — Training Dataset Audit

Source: `data/training_dataset.csv`  
Shape: **4000 rows x 44 columns**

## 1. Null report (all columns, sorted by null %)

|                              | dtype   |   null_count |   null_pct |
|:-----------------------------|:--------|-------------:|-----------:|
| dom_credential_form_detected | float64 |         4000 |     100    |
| visual_similarity_score      | float64 |         4000 |     100    |
| whois_registrar              | object  |         1947 |      48.68 |
| whois_domain_age_days        | float64 |         1897 |      47.42 |
| ssl_days_until_expiry        | float64 |         1379 |      34.48 |
| ssl_issuer                   | object  |         1379 |      34.48 |
| ssl_expired                  | object  |         1077 |      26.92 |
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
| whois_registrar       | object  |         1947 |      48.68 |
| whois_domain_age_days | float64 |         1897 |      47.42 |
| ssl_days_until_expiry | float64 |         1379 |      34.48 |
| ssl_issuer            | object  |         1379 |      34.48 |
| ssl_expired           | object  |         1077 |      26.92 |

## 4. Categorical cardinality (encoding strategy inputs)

### `tld`

- Unique values (excluding null): **212**
- Non-null rows: 4000 / 4000
- Top 10 values cover: **71.9%** of non-null rows

| value | count | pct of non-null |
|---|---|---|
| com | 1409 | 35.23% |
| dev | 398 | 9.95% |
| app | 321 | 8.03% |
| io | 218 | 5.45% |
| net | 162 | 4.05% |
| org | 111 | 2.77% |
| ru | 91 | 2.27% |
| xyz | 65 | 1.62% |
| cn | 53 | 1.32% |
| gr | 48 | 1.2% |

### `whois_registrar`

- Unique values (excluding null): **312**
- Non-null rows: 2053 / 4000
- Top 10 values cover: **44.62%** of non-null rows

| value | count | pct of non-null |
|---|---|---|
| GoDaddy.com, LLC | 232 | 11.3% |
| MarkMonitor, Inc. | 144 | 7.01% |
| NameCheap, Inc. | 143 | 6.97% |
| Amazon Registrar, Inc. | 76 | 3.7% |
| Cloudflare, Inc. | 63 | 3.07% |
| MarkMonitor Inc. | 62 | 3.02% |
| Network Solutions, LLC | 52 | 2.53% |
| Gname.com Pte. Ltd. | 49 | 2.39% |
| RU-CENTER-RU | 48 | 2.34% |
| TUCOWS.COM, CO. | 47 | 2.29% |

### `ssl_issuer`

- Unique values (excluding null): **48**
- Non-null rows: 2621 / 4000
- Top 10 values cover: **96.6%** of non-null rows

| value | count | pct of non-null |
|---|---|---|
| Google Trust Services | 1036 | 39.53% |
| Let's Encrypt | 843 | 32.16% |
| DigiCert Inc | 221 | 8.43% |
| Amazon | 178 | 6.79% |
| Sectigo Limited | 89 | 3.4% |
| GlobalSign nv-sa | 88 | 3.36% |
| Hellenic Academic and Research Institutions CA | 21 | 0.8% |
| ZeroSSL GmbH | 20 | 0.76% |
| GoDaddy.com, Inc. | 18 | 0.69% |
| DigiCert, Inc. | 18 | 0.69% |

## 5. Numeric column summary

|                              |   count |     mean |      std |     min |      25% |      50% |      75% |       max |
|:-----------------------------|--------:|---------:|---------:|--------:|---------:|---------:|---------:|----------:|
| label                        |    4000 |    0.5   |    0.5   |   0     |    0     |    0.5   |    1     |     1     |
| url_length                   |    4000 |   39.276 |   29.898 |  12     |   26     |   34     |   44     |   991     |
| hyphen_count                 |    4000 |    0.676 |    1.324 |   0     |    0     |    0     |    1     |    10     |
| dot_count                    |    4000 |    1.744 |    0.703 |   1     |    1     |    2     |    2     |     7     |
| digit_count                  |    4000 |    1.062 |    2.415 |   0     |    0     |    0     |    1     |    29     |
| entropy                      |    4000 |    3.454 |    0.51  |   0.755 |    3.122 |    3.432 |    3.796 |     4.914 |
| subdomain_depth              |    4000 |    0.744 |    0.703 |   0     |    0     |    1     |    1     |     6     |
| has_https                    |    4000 |    0.8   |    0.4   |   0     |    1     |    1     |    1     |     1     |
| is_ip_address                |    4000 |    0     |    0     |   0     |    0     |    0     |    0     |     0     |
| has_at_symbol                |    4000 |    0.003 |    0.055 |   0     |    0     |    0     |    0     |     1     |
| path_length                  |    4000 |    7.104 |   12.37  |   0     |    0     |    0     |   11     |   190     |
| query_param_count            |    4000 |    0.104 |    0.491 |   0     |    0     |    0     |    0     |    12     |
| special_char_count           |    4000 |    0.272 |    1.454 |   0     |    0     |    0     |    0     |    54     |
| brand_impersonation_score    |    4000 |    0.026 |    0.064 |   0     |    0     |    0     |    0     |     0.5   |
| brand_matched_count          |    4000 |    0.265 |    0.622 |   0     |    0     |    0     |    0     |     4     |
| brand_keyword_hit_count      |    4000 |    0.003 |    0.052 |   0     |    0     |    0     |    0     |     1     |
| brand_typosquat_hit_count    |    4000 |    0.269 |    0.639 |   0     |    0     |    0     |    0     |     5     |
| brand_has_action_word        |    4000 |    0.019 |    0.136 |   0     |    0     |    0     |    0     |     1     |
| tld_risk_score               |    4000 |    0.339 |    0.197 |   0.01  |    0.15  |    0.35  |    0.5   |     0.94  |
| tld_known                    |    4000 |    0.635 |    0.482 |   0     |    0     |    1     |    1     |     1     |
| idn_is_homograph             |    4000 |    0.002 |    0.039 |   0     |    0     |    0     |    0     |     1     |
| idn_confusable_count         |    4000 |    0     |    0     |   0     |    0     |    0     |    0     |     0     |
| idn_risk_score               |    4000 |    0.001 |    0.023 |   0     |    0     |    0     |    0     |     0.6   |
| idn_punycode_flag            |    4000 |    0.002 |    0.039 |   0     |    0     |    0     |    0     |     1     |
| dns_a_record_count           |    4000 |    1.588 |    1.411 |   0     |    1     |    2     |    2     |    40     |
| dns_has_aaaa                 |    4000 |    0     |    0     |   0     |    0     |    0     |    0     |     0     |
| dns_has_mx                   |    4000 |    0.186 |    0.389 |   0     |    0     |    0     |    0     |     1     |
| whois_domain_age_days        |    2103 | 5153.04  | 3896.53  |   0     | 1458.5   | 4728     | 8504.5   | 14998     |
| whois_recently_registered    |    4000 |    0.035 |    0.183 |   0     |    0     |    0     |    0     |     1     |
| whois_privacy_protected      |    4000 |    0.105 |    0.307 |   0     |    0     |    0     |    0     |     1     |
| whois_found                  |    4000 |    0.542 |    0.498 |   0     |    0     |    1     |    1     |     1     |
| ssl_self_signed              |    4000 |    0     |    0     |   0     |    0     |    0     |    0     |     0     |
| ssl_days_until_expiry        |    2621 |   80.412 |   50.092 |   2     |   47     |   70     |   86     |   253     |
| visual_similarity_score      |       0 |  nan     |  nan     | nan     |  nan     |  nan     |  nan     |   nan     |
| dom_credential_form_detected |       0 |  nan     |  nan     | nan     |  nan     |  nan     |  nan     |   nan     |
| aggregate_lexical_risk_score |    4000 |    0.181 |    0.07  |   0.051 |    0.115 |    0.196 |    0.223 |     0.411 |

## 6. Suspicious value checks

- Label distribution: {1: 2000, 0: 2000} (expected 2000/2000 per handoff).
- **8** duplicate `url` values found (handoff claims dedup during collection — worth confirming).
