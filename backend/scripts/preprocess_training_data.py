"""
PhishGuard AI - Phase 3.2, Step 2: Preprocessing / feature engineering.

Reads backend/data/training_dataset.csv and produces a clean, fully-numeric
training matrix ready for model training.

Updated (Phase 4 integration): visual_similarity_score and
dom_credential_form_detected are REAL Phase 4 output now (no longer 100%
null stubs), so they are kept and imputed like any other partially-missing
feature rather than dropped. category is frequency-encoded (same treatment
as tld/whois_registrar). closest_brand is dropped - at current dataset
size it is ~99.9% null (screenshot capture only succeeds for a fraction of
scanned URLs, and brand matches are rare even then), so there isn't enough
signal yet to justify keeping it; revisit once more data is collected.

Outputs (all under backend/data/):
  - training_features.csv       - X, fully numeric, no nulls, model-ready
  - training_labels.csv         - y (label column, aligned by row index)
  - training_ids.csv            - url, domain kept for traceability/debugging
  - preprocessing_artifacts.json - frequency maps + ssl_issuer top-10 list,
                                    needed at inference time.

Run:
    docker compose exec api python scripts/preprocess_training_data.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pandas as pd

DATA_DIR = Path("data")
INPUT_PATH = DATA_DIR / "training_dataset.csv"

OUT_FEATURES = DATA_DIR / "training_features.csv"
OUT_LABELS = DATA_DIR / "training_labels.csv"
OUT_IDS = DATA_DIR / "training_ids.csv"
OUT_ARTIFACTS = DATA_DIR / "preprocessing_artifacts.json"

ID_COLS = ["url", "domain"]
LABEL_COL = "label"

# closest_brand: near-total null (~99.9%) at current dataset size, not
# enough signal yet to justify keeping - dropped, same treatment the
# original script gave visual_similarity_score/dom_credential_form_detected
# back when THOSE were 100% null stubs.
DROPPED_LOW_SIGNAL_COLS = ["closest_brand"]

SENTINEL = -1  # for numeric columns where real values are always >= 0

FREQ_ENCODE_COLS = ["tld", "whois_registrar", "category"]

SSL_ISSUER_COL = "ssl_issuer"
SSL_ISSUER_TOP_N = 10

NUMERIC_SENTINEL_COLS = [
    "whois_domain_age_days",
    "ssl_days_until_expiry",
    "visual_similarity_score",
]

# Boolean-ish columns (True/False/NaN as object dtype) needing explicit
# 1/0/sentinel mapping, same pattern as ssl_expired.
BOOLEAN_SENTINEL_COLS = ["ssl_expired", "dom_credential_form_detected"]

# Columns that get an explicit `_was_missing` flag: genuine lookup/capture
# failures, not stubs.
MISSINGNESS_FLAG_COLS = [
    "whois_registrar",
    "whois_domain_age_days",
    "ssl_days_until_expiry",
    "ssl_issuer",
    "ssl_expired",
    "visual_similarity_score",
    "dom_credential_form_detected",
    "category",
]


def load_dataset(path: Path) -> pd.DataFrame:
    if not path.exists():
        print(f"ERROR: {path} not found. Run from backend/ (i.e. /app in the container).", file=sys.stderr)
        sys.exit(1)
    return pd.read_csv(path)


def sanitize_col_name(value: str) -> str:
    """Turn a raw category value into a safe column-name suffix."""
    return (
        str(value)
        .strip()
        .lower()
        .replace(" ", "_")
        .replace(",", "")
        .replace(".", "")
        .replace("-", "_")
        .replace("(", "")
        .replace(")", "")
    )


def add_missingness_flags(df: pd.DataFrame) -> pd.DataFrame:
    for col in MISSINGNESS_FLAG_COLS:
        df[f"{col}_was_missing"] = df[col].isnull().astype(int)
    return df


def impute_numeric_sentinels(df: pd.DataFrame) -> pd.DataFrame:
    for col in NUMERIC_SENTINEL_COLS:
        df[col] = df[col].fillna(SENTINEL)
    return df


def encode_boolean_sentinels(df: pd.DataFrame) -> pd.DataFrame:
    """Map True/False/NaN-mix object columns to 1/0/sentinel. The
    _was_missing flag already added separately covers the NaN case
    explicitly for the model."""
    mapping = {True: 1, False: 0, "True": 1, "False": 0, "true": 1, "false": 0}
    for col in BOOLEAN_SENTINEL_COLS:
        df[col] = df[col].map(mapping)
        df[col] = df[col].fillna(SENTINEL).astype(int)
    return df


def fit_frequency_encoding(df: pd.DataFrame, col: str) -> dict:
    """Frequency = proportion of rows with this exact value, treating NaN
    as its own category so 'missing' gets a real, informative frequency
    rather than silently mapping to 0."""
    counts = df[col].value_counts(normalize=True, dropna=False)
    freq_map = {}
    for key, freq in counts.items():
        key_str = "__missing__" if pd.isnull(key) else str(key)
        freq_map[key_str] = round(float(freq), 6)
    return freq_map


def apply_frequency_encoding(df: pd.DataFrame, col: str, freq_map: dict) -> pd.DataFrame:
    def lookup(val):
        key = "__missing__" if pd.isnull(val) else str(val)
        return freq_map.get(key, freq_map.get("__missing__", 0.0))

    df[f"{col}_freq"] = df[col].apply(lookup)
    df = df.drop(columns=[col])
    return df


def fit_ssl_issuer_top_n(df: pd.DataFrame, top_n: int) -> list[str]:
    vc = df[SSL_ISSUER_COL].dropna().value_counts()
    return vc.head(top_n).index.tolist()


def apply_ssl_issuer_onehot(df: pd.DataFrame, top_values: list[str]) -> pd.DataFrame:
    for val in top_values:
        col_name = f"ssl_issuer_{sanitize_col_name(val)}"
        df[col_name] = (df[SSL_ISSUER_COL] == val).astype(int)

    is_missing = df[SSL_ISSUER_COL].isnull()
    is_known_top = df[SSL_ISSUER_COL].isin(top_values)
    df["ssl_issuer_other"] = (~is_missing & ~is_known_top).astype(int)
    df["ssl_issuer_missing"] = is_missing.astype(int)

    df = df.drop(columns=[SSL_ISSUER_COL])
    return df


def cast_bools_to_int(df: pd.DataFrame) -> pd.DataFrame:
    bool_cols = df.select_dtypes(include="bool").columns
    for col in bool_cols:
        df[col] = df[col].astype(int)
    return df


def validate_final_matrix(df: pd.DataFrame) -> None:
    null_counts = df.isnull().sum()
    remaining_nulls = null_counts[null_counts > 0]
    if not remaining_nulls.empty:
        print("ERROR: nulls remain after preprocessing:", file=sys.stderr)
        print(remaining_nulls, file=sys.stderr)
        sys.exit(1)

    non_numeric = df.select_dtypes(exclude="number").columns.tolist()
    if non_numeric:
        print(f"ERROR: non-numeric columns remain: {non_numeric}", file=sys.stderr)
        sys.exit(1)

    print(f"Validation OK: {df.shape[0]} rows x {df.shape[1]} columns, all numeric, no nulls.")


def main() -> None:
    df = load_dataset(INPUT_PATH)
    print(f"Loaded {INPUT_PATH}: {df.shape[0]} rows x {df.shape[1]} columns")

    ids_df = df[ID_COLS].copy()
    y = df[[LABEL_COL]].copy()

    df = df.drop(columns=ID_COLS + [LABEL_COL] + DROPPED_LOW_SIGNAL_COLS)
    print(f"Dropped id cols {ID_COLS}, label, and low-signal cols {DROPPED_LOW_SIGNAL_COLS}")

    df = add_missingness_flags(df)
    df = impute_numeric_sentinels(df)
    df = encode_boolean_sentinels(df)

    artifacts = {"sentinel_value": SENTINEL, "frequency_encoding": {}, "ssl_issuer_top_values": []}

    for col in FREQ_ENCODE_COLS:
        freq_map = fit_frequency_encoding(df, col)
        artifacts["frequency_encoding"][col] = freq_map
        df = apply_frequency_encoding(df, col, freq_map)
        print(f"Frequency-encoded `{col}` ({len(freq_map)} distinct values incl. __missing__)")

    top_issuers = fit_ssl_issuer_top_n(df, SSL_ISSUER_TOP_N)
    artifacts["ssl_issuer_top_values"] = top_issuers
    df = apply_ssl_issuer_onehot(df, top_issuers)
    print(f"One-hot encoded `ssl_issuer`: top {len(top_issuers)} + other + missing")

    df = cast_bools_to_int(df)

    validate_final_matrix(df)

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    df.to_csv(OUT_FEATURES, index=False)
    y.to_csv(OUT_LABELS, index=False)
    ids_df.to_csv(OUT_IDS, index=False)
    with open(OUT_ARTIFACTS, "w", encoding="utf-8") as f:
        json.dump(artifacts, f, indent=2)

    print(f"\nWrote {OUT_FEATURES} ({df.shape[0]} x {df.shape[1]})")
    print(f"Wrote {OUT_LABELS}")
    print(f"Wrote {OUT_IDS}")
    print(f"Wrote {OUT_ARTIFACTS}")
    print(f"\nFinal feature columns ({len(df.columns)}):")
    for col in df.columns:
        print(f"  - {col}")


if __name__ == "__main__":
    main()
