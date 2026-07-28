"""
PhishGuard AI — Phase 3.2, Step 1: Training dataset audit.

Purpose: pure diagnostics on backend/data/training_dataset.csv BEFORE any
preprocessing decisions are locked in. Answers, with real numbers:
  - What's the actual null rate per column (vs. the known 100%-null
    Phase 4 stubs)?
  - How high is the cardinality of the free-text categorical columns
    (tld, whois_registrar, ssl_issuer)? Determines whether "top-N + other"
    bucketing or frequency/target encoding makes more sense.
  - Any numeric columns with out-of-range / suspicious values worth
    catching before they get fed into a model?

Does NOT modify training_dataset.csv. Writes a report to
backend/data/phase3_2_audit.md and also prints a summary to stdout.

Run inside the container (per the handoff's known-gotchas: service is
`api`, not `backend`):

    docker compose exec api python scripts/analyze_training_dataset.py

Expects to be run from /app (the bind-mounted backend/ dir), reading
data/training_dataset.csv and writing data/phase3_2_audit.md.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd

DATA_PATH = Path("data/training_dataset.csv")
REPORT_PATH = Path("data/phase3_2_audit.md")

# Columns we already know are non-feature (traceability only, per handoff).
NON_FEATURE_COLS = ["url", "domain"]
LABEL_COL = "label"

# Columns known going in to be permanently None until Phase 4 lands.
KNOWN_PHASE4_STUBS = ["visual_similarity_score", "dom_credential_form_detected"]

# Free-text categorical columns flagged in the handoff as needing an
# encoding strategy.
HIGH_CARDINALITY_CANDIDATES = ["tld", "whois_registrar", "ssl_issuer"]

TOP_N_FOR_COVERAGE = 10  # how many top values to check coverage for


def load_dataset(path: Path) -> pd.DataFrame:
    if not path.exists():
        print(f"ERROR: {path} not found. Run this from the backend/ directory "
              f"(i.e. /app inside the container).", file=sys.stderr)
        sys.exit(1)
    df = pd.read_csv(path)
    return df


def null_report(df: pd.DataFrame) -> pd.DataFrame:
    n = len(df)
    nulls = df.isnull().sum()
    pct = (nulls / n * 100).round(2)
    dtypes = df.dtypes.astype(str)
    out = pd.DataFrame({
        "dtype": dtypes,
        "null_count": nulls,
        "null_pct": pct,
    })
    out = out.sort_values("null_pct", ascending=False)
    return out


def categorical_cardinality_report(df: pd.DataFrame, cols: list[str]) -> str:
    lines = []
    for col in cols:
        if col not in df.columns:
            lines.append(f"### `{col}`\n\n(column not found in dataset — skipped)\n")
            continue
        series = df[col]
        non_null = series.dropna()
        n_non_null = len(non_null)
        n_unique = non_null.nunique()
        lines.append(f"### `{col}`")
        lines.append("")
        lines.append(f"- Unique values (excluding null): **{n_unique}**")
        lines.append(f"- Non-null rows: {n_non_null} / {len(series)}")
        if n_non_null > 0:
            vc = non_null.value_counts()
            top_n = vc.head(TOP_N_FOR_COVERAGE)
            coverage_pct = round(top_n.sum() / n_non_null * 100, 2)
            lines.append(f"- Top {TOP_N_FOR_COVERAGE} values cover: **{coverage_pct}%** of non-null rows")
            lines.append("")
            lines.append("| value | count | pct of non-null |")
            lines.append("|---|---|---|")
            for val, cnt in top_n.items():
                pct = round(cnt / n_non_null * 100, 2)
                val_display = str(val)[:60]  # guard against absurdly long strings
                lines.append(f"| {val_display} | {cnt} | {pct}% |")
        lines.append("")
    return "\n".join(lines)


def numeric_describe_report(df: pd.DataFrame) -> str:
    numeric_df = df.select_dtypes(include="number")
    if numeric_df.empty:
        return "(no numeric columns detected)\n"
    desc = numeric_df.describe().T
    desc = desc.round(3)
    return desc.to_markdown()


def suspicious_value_checks(df: pd.DataFrame) -> list[str]:
    """Flag a few known-risky patterns rather than trying to be exhaustive."""
    flags = []

    if "whois_domain_age_days" in df.columns:
        neg = (df["whois_domain_age_days"] < 0).sum()
        if neg > 0:
            flags.append(f"- `whois_domain_age_days` has **{neg}** negative values (should never be negative).")

    if "ssl_days_until_expiry" in df.columns:
        neg = (df["ssl_days_until_expiry"] < 0).sum()
        if neg > 0:
            flags.append(
                f"- `ssl_days_until_expiry` has **{neg}** negative values — check whether these are "
                f"already-expired certs (in which case `ssl_expired` should independently confirm this, "
                f"worth cross-checking the two columns agree) or a bug."
            )

    if "label" in df.columns:
        vc = df["label"].value_counts()
        flags.append(f"- Label distribution: {vc.to_dict()} (expected 2000/2000 per handoff).")

    dup_urls = df["url"].duplicated().sum() if "url" in df.columns else 0
    if dup_urls > 0:
        flags.append(f"- **{dup_urls}** duplicate `url` values found (handoff claims dedup during collection — worth confirming).")

    if not flags:
        flags.append("- No suspicious patterns flagged by these checks.")

    return flags


def main() -> None:
    df = load_dataset(DATA_PATH)
    n_rows, n_cols = df.shape

    print(f"Loaded {DATA_PATH}: {n_rows} rows x {n_cols} columns")

    nulls = null_report(df)

    stub_status = []
    for col in KNOWN_PHASE4_STUBS:
        if col in df.columns:
            pct = nulls.loc[col, "null_pct"] if col in nulls.index else None
            stub_status.append((col, pct))

    lookup_null_cols = nulls[
        (nulls["null_pct"] > 0) & (~nulls.index.isin(KNOWN_PHASE4_STUBS))
    ]

    report_lines = []
    report_lines.append("# Phase 3.2 — Training Dataset Audit\n")
    report_lines.append(f"Source: `{DATA_PATH}`  \nShape: **{n_rows} rows x {n_cols} columns**\n")

    report_lines.append("## 1. Null report (all columns, sorted by null %)\n")
    report_lines.append(nulls.to_markdown())
    report_lines.append("")

    report_lines.append("## 2. Phase 4 stub columns (expected 100% null)\n")
    for col, pct in stub_status:
        status = "OK — 100% null as expected" if pct == 100.0 else f"UNEXPECTED — {pct}% null, not 100%"
        report_lines.append(f"- `{col}`: {status}")
    report_lines.append("")

    report_lines.append("## 3. Lookup-derived columns with genuine (non-stub) missingness\n")
    if lookup_null_cols.empty:
        report_lines.append("(none found — unexpected given handoff notes about WHOIS/SSL failures)\n")
    else:
        report_lines.append(
            "These are the columns where missingness reflects real lookup failures "
            "(NXDOMAIN, no cert, WHOIS timeout, etc.) rather than an unbuilt feature. "
            "Per the handoff, this missingness may itself be signal and is a candidate "
            "for a `_was_missing` companion boolean rather than silent imputation.\n"
        )
        report_lines.append(lookup_null_cols.to_markdown())
    report_lines.append("")

    report_lines.append("## 4. Categorical cardinality (encoding strategy inputs)\n")
    report_lines.append(categorical_cardinality_report(df, HIGH_CARDINALITY_CANDIDATES))

    report_lines.append("## 5. Numeric column summary\n")
    report_lines.append(numeric_describe_report(df))
    report_lines.append("")

    report_lines.append("## 6. Suspicious value checks\n")
    for line in suspicious_value_checks(df):
        report_lines.append(line)
    report_lines.append("")

    report_text = "\n".join(report_lines)
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.write_text(report_text, encoding="utf-8")

    print(f"\nFull report written to {REPORT_PATH}")
    print("\n--- Quick summary ---")
    print(f"Phase 4 stub columns: {stub_status}")
    print(f"Columns with genuine lookup-failure nulls: {list(lookup_null_cols.index)}")
    for col in HIGH_CARDINALITY_CANDIDATES:
        if col in df.columns:
            print(f"{col}: {df[col].nunique()} unique values")


if __name__ == "__main__":
    main()
