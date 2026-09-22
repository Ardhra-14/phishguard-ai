# Phase 3.2 — Training Dataset Audit

Source: `data/training_dataset.csv`  
Shape: **4848 rows x 46 columns**

## 1. Null report (all columns, sorted by null %)

|                              | dtype   |   null_count |   null_pct |
|:-----------------------------|:--------|-------------:|-----------:|
| closest_brand                | object  |         4846 |      99.96 |
| category                     | object  |         3773 |      77.83 |
| whois_domain_age_days        | float64 |         2784 |      57.43 |
| whois_registrar              | object  |         2780 |      57.34 |
| ssl_days_until_expiry        | float64 |         2195 |      45.28 |
| ssl_issuer                   | object  |         2195 |      45.28 |
| ssl_expired                  | object  |         1872 |      38.61 |
| dom_credential_form_detected | object  |         1681 |      34.67 |
| visual_similarity_score      | float64 |         1681 |      34.67 |
| url                          | object  |            0 |       0    |
| dns_has_aaaa                 | int64   |            0 |       0    |
| idn_risk_score               | float64 |            0 |       0    |
| idn_punycode_flag            | int64   |            0 |       0    |
| dns_resolves                 | bool    |            0 |       0    |
| dns_a_record_count           | int64   |            0 |       0    |
| whois_privacy_protected      | int64   |            0 |       0    |
| dns_has_mx                   | int64   |            0 |       0    |
| whois_recently_registered    | int64   |            0 |       0    |
| idn_is_homograph             | int64   |            0 |       0    |
| whois_found                  | int64   |            0 |       0    |
| ssl_valid                    | bool    |            0 |       0    |
| ssl_self_signed              | int64   |            0 |       0    |
| idn_confusable_count         | int64   |            0 |       0    |
| tld_known                    | int64   |            0 |       0    |
| domain                       | object  |            0 |       0    |
| tld_risk_score               | float64 |            0 |       0    |
| label                        | int64   |            0 |       0    |
| url_length                   | int64   |            0 |       0    |
| hyphen_count                 | int64   |            0 |       0    |
| dot_count                    | int64   |            0 |       0    |
| digit_count                  | int64   |            0 |       0    |
| entropy                      | float64 |            0 |       0    |
| subdomain_depth              | int64   |            0 |       0    |
| has_https                    | int64   |            0 |       0    |
| is_ip_address                | int64   |            0 |       0    |
| has_at_symbol                | int64   |            0 |       0    |
| path_length                  | int64   |            0 |       0    |
| query_param_count            | int64   |            0 |       0    |
| special_char_count           | int64   |            0 |       0    |
| brand_impersonation_score    | float64 |            0 |       0    |
| brand_matched_count          | int64   |            0 |       0    |
| brand_keyword_hit_count      | int64   |            0 |       0    |
| brand_typosquat_hit_count    | int64   |            0 |       0    |
| brand_has_action_word        | int64   |            0 |       0    |
| tld                          | object  |            0 |       0    |
| aggregate_lexical_risk_score | float64 |            0 |       0    |

## 2. Phase 4 stub columns (expected 100% null)

- `visual_similarity_score`: UNEXPECTED — 34.67% null, not 100%
- `dom_credential_form_detected`: UNEXPECTED — 34.67% null, not 100%

## 3. Lookup-derived columns with genuine (non-stub) missingness

These are the columns where missingness reflects real lookup failures (NXDOMAIN, no cert, WHOIS timeout, etc.) rather than an unbuilt feature. Per the handoff, this missingness may itself be signal and is a candidate for a `_was_missing` companion boolean rather than silent imputation.

|                       | dtype   |   null_count |   null_pct |
|:----------------------|:--------|-------------:|-----------:|
| closest_brand         | object  |         4846 |      99.96 |
| category              | object  |         3773 |      77.83 |
| whois_domain_age_days | float64 |         2784 |      57.43 |
| whois_registrar       | object  |         2780 |      57.34 |
| ssl_days_until_expiry | float64 |         2195 |      45.28 |
| ssl_issuer            | object  |         2195 |      45.28 |
| ssl_expired           | object  |         1872 |      38.61 |

## 4. Categorical cardinality (encoding strategy inputs)

### `tld`

- Unique values (excluding null): **213**
- Non-null rows: 4848 / 4848
- Top 10 values cover: **73.97%** of non-null rows

| value | count | pct of non-null |
|---|---|---|
| com | 1737 | 35.83% |
| dev | 538 | 11.1% |
| app | 481 | 9.92% |
| io | 223 | 4.6% |
| net | 206 | 4.25% |
| org | 121 | 2.5% |
| ru | 110 | 2.27% |
| de | 77 | 1.59% |
| cn | 47 | 0.97% |
| ml | 46 | 0.95% |

### `whois_registrar`

- Unique values (excluding null): **255**
- Non-null rows: 2068 / 4848
- Top 10 values cover: **54.16%** of non-null rows

| value | count | pct of non-null |
|---|---|---|
| GoDaddy.com, LLC | 307 | 14.85% |
| MarkMonitor, Inc. | 216 | 10.44% |
| NAMECHEAP INC | 172 | 8.32% |
| Amazon Registrar, Inc. | 88 | 4.26% |
| Dynadot Inc | 79 | 3.82% |
| RU-CENTER-RU | 68 | 3.29% |
| Cloudflare, Inc. | 63 | 3.05% |
| Network Solutions, LLC | 46 | 2.22% |
| GANDI SAS | 43 | 2.08% |
| NameSilo, LLC | 38 | 1.84% |

### `ssl_issuer`

- Unique values (excluding null): **44**
- Non-null rows: 2653 / 4848
- Top 10 values cover: **96.42%** of non-null rows

| value | count | pct of non-null |
|---|---|---|
| Google Trust Services | 1290 | 48.62% |
| Let's Encrypt | 664 | 25.03% |
| DigiCert Inc | 192 | 7.24% |
| Amazon | 179 | 6.75% |
| GlobalSign nv-sa | 95 | 3.58% |
| Sectigo Limited | 89 | 3.35% |
| GoDaddy.com, Inc. | 17 | 0.64% |
| GoDaddy.com | 11 | 0.41% |
| Hellenic Academic and Research Institutions CA | 11 | 0.41% |
| Microsoft Corporation | 10 | 0.38% |

## 5. Numeric column summary

|                              |   count |     mean |      std |    min |      25% |      50% |      75% |       max |
|:-----------------------------|--------:|---------:|---------:|-------:|---------:|---------:|---------:|----------:|
| label                        |    4848 |    0.493 |    0.5   |  0     |    0     |    0     |    1     |     1     |
| url_length                   |    4848 |   40.256 |   32.367 | 13     |   26     |   34     |   45     |  1111     |
| hyphen_count                 |    4848 |    0.586 |    1.165 |  0     |    0     |    0     |    1     |     7     |
| dot_count                    |    4848 |    1.727 |    0.782 |  1     |    1     |    2     |    2     |     7     |
| digit_count                  |    4848 |    1.094 |    2.861 |  0     |    0     |    0     |    1     |    27     |
| entropy                      |    4848 |    3.429 |    0.499 |  1.918 |    3.096 |    3.418 |    3.778 |     4.825 |
| subdomain_depth              |    4848 |    0.727 |    0.782 |  0     |    0     |    1     |    1     |     6     |
| has_https                    |    4848 |    0.826 |    0.379 |  0     |    1     |    1     |    1     |     1     |
| is_ip_address                |    4848 |    0.006 |    0.077 |  0     |    0     |    0     |    0     |     1     |
| has_at_symbol                |    4848 |    0.002 |    0.048 |  0     |    0     |    0     |    0     |     1     |
| path_length                  |    4848 |    9.182 |   12.985 |  0     |    0     |    6     |   14     |   116     |
| query_param_count            |    4848 |    0.081 |    0.395 |  0     |    0     |    0     |    0     |     9     |
| special_char_count           |    4848 |    0.225 |    1.782 |  0     |    0     |    0     |    0     |    98     |
| brand_impersonation_score    |    4848 |    0.027 |    0.061 |  0     |    0     |    0     |    0     |     0.65  |
| brand_matched_count          |    4848 |    0.281 |    0.599 |  0     |    0     |    0     |    0     |     5     |
| brand_keyword_hit_count      |    4848 |    0.002 |    0.048 |  0     |    0     |    0     |    0     |     1     |
| brand_typosquat_hit_count    |    4848 |    0.284 |    0.617 |  0     |    0     |    0     |    0     |     6     |
| brand_has_action_word        |    4848 |    0.018 |    0.133 |  0     |    0     |    0     |    0     |     1     |
| tld_risk_score               |    4848 |    0.328 |    0.184 |  0.01  |    0.15  |    0.3   |    0.5   |     0.94  |
| tld_known                    |    4848 |    0.638 |    0.481 |  0     |    0     |    1     |    1     |     1     |
| idn_is_homograph             |    4848 |    0.001 |    0.038 |  0     |    0     |    0     |    0     |     1     |
| idn_confusable_count         |    4848 |    0     |    0     |  0     |    0     |    0     |    0     |     0     |
| idn_risk_score               |    4848 |    0.001 |    0.023 |  0     |    0     |    0     |    0     |     0.6   |
| idn_punycode_flag            |    4848 |    0.001 |    0.038 |  0     |    0     |    0     |    0     |     1     |
| dns_a_record_count           |    4848 |    1.69  |    1.399 |  0     |    1     |    2     |    2     |    20     |
| dns_has_aaaa                 |    4848 |    0     |    0     |  0     |    0     |    0     |    0     |     0     |
| dns_has_mx                   |    4848 |    0.285 |    0.451 |  0     |    0     |    0     |    1     |     1     |
| whois_domain_age_days        |    2064 | 5219.1   | 3886.79  |  0     | 1573     | 5026.5   | 8288.5   | 15114     |
| whois_recently_registered    |    4848 |    0.031 |    0.172 |  0     |    0     |    0     |    0     |     1     |
| whois_privacy_protected      |    4848 |    0.113 |    0.317 |  0     |    0     |    0     |    0     |     1     |
| whois_found                  |    4848 |    0.44  |    0.496 |  0     |    0     |    0     |    1     |     1     |
| ssl_self_signed              |    4848 |    0     |    0     |  0     |    0     |    0     |    0     |     0     |
| ssl_days_until_expiry        |    2653 |   78.311 |   38.637 |  3     |   52     |   75     |   84     |   215     |
| visual_similarity_score      |    3167 |    0.233 |    0.133 |  0     |    0.125 |    0.25  |    0.312 |     1     |
| aggregate_lexical_risk_score |    4848 |    0.178 |    0.065 |  0.051 |    0.115 |    0.195 |    0.221 |     0.515 |

## 6. Suspicious value checks

- Label distribution: {0: 2458, 1: 2390} (expected 2000/2000 per handoff).
- **2** duplicate `url` values found (handoff claims dedup during collection — worth confirming).
