"""
Phase 3.4 — Step 1: XGBoost baseline, untuned.

Reconstructed [this session] from tune_xgboost.py's plumbing after the
original Step 1 script was found to have been accidentally committed with
tune_xgboost.py's content under this filename (pre-existing issue, found
during the Phase 3.5 dataset rebuild — see phase3_5_path_length_check.md
for the unrelated leak investigation that led here). Same data loading,
train/test split, metrics, and report-writing pattern as the real
tune_xgboost.py, with the RandomizedSearchCV wrapper removed and a single
plain XGBClassifier fit in its place — this is the "no tuning" comparison
point that Step 3 (tuning) and Step 5 (ensemble) are measured against.

Same stratified 80/20 holdout split as 3.3 (random_state=42) so all four
models (RF / XGB untuned / XGB tuned / Ensemble) stay comparable.

Container path:
  host:      backend/scripts/train_xgboost_baseline.py
  container: scripts/train_xgboost_baseline.py

Run inside the api container:
  docker compose exec api python scripts/train_xgboost_baseline.py
"""

import json
from pathlib import Path

import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
)
from xgboost import XGBClassifier

DATA_DIR = Path("data")
FEATURES_PATH = DATA_DIR / "training_features.csv"
LABELS_PATH = DATA_DIR / "training_labels.csv"
REPORT_PATH = DATA_DIR / "phase3_4_baseline_results.md"

RANDOM_STATE = 42
TEST_SIZE = 0.20

# Baseline to compare against in the report — pulled from the current
# Phase 3.3 rebuild results (post Phase-3.1-fix-v2 dataset), not the
# original pre-rebuild numbers.
RF_BASELINE = {
    "accuracy": 0.9725, "precision": 0.9773, "recall": 0.9675,
    "f1": 0.9724, "roc_auc": 0.9968,
}


def load_data():
    X = pd.read_csv(FEATURES_PATH)
    y = pd.read_csv(LABELS_PATH).squeeze("columns")
    return X, y


def train_untuned(X_train, y_train):
    model = XGBClassifier(
        random_state=RANDOM_STATE,
        n_jobs=-1,
        eval_metric="logloss",
    )
    model.fit(X_train, y_train)
    return model


def evaluate(model, X_test, y_test):
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1]
    metrics = {
        "accuracy": accuracy_score(y_test, y_pred),
        "precision": precision_score(y_test, y_pred),
        "recall": recall_score(y_test, y_pred),
        "f1": f1_score(y_test, y_pred),
        "roc_auc": roc_auc_score(y_test, y_proba),
    }
    cm = confusion_matrix(y_test, y_pred)
    return metrics, cm


def write_report(metrics, cm, importances, n_test):
    lines = []
    lines.append("# Phase 3.4 — XGBoost Untuned Baseline Results (Step 1)\n")
    lines.append("Plain XGBClassifier(random_state=42, n_jobs=-1), no hyperparameter search.\n")
    lines.append(f"Held-out test set: n={n_test}\n")
    lines.append("## Two-way comparison (held-out test set)\n")
    lines.append("| Metric | RF (3.3) | XGB untuned (3.4-1) | Delta |")
    lines.append("|---|---|---|---|")
    for k in metrics:
        delta = metrics[k] - RF_BASELINE[k]
        lines.append(
            f"| {k} | {RF_BASELINE[k]:.4f} | {metrics[k]:.4f} | {delta:+.4f} |"
        )
    lines.append("")
    lines.append(f"Confusion matrix: `{cm.tolist()}`\n")
    lines.append("## Top 10 features by importance\n")
    lines.append("| Feature | Importance |")
    lines.append("|---|---|")
    for feat, imp in importances.head(10).items():
        lines.append(f"| {feat} | {imp:.3f} |")
    lines.append("")

    REPORT_PATH.write_text("\n".join(lines), encoding="utf-8")
    print(f"Report written to {REPORT_PATH}")


def main():
    X, y = load_data()
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=TEST_SIZE, stratify=y, random_state=RANDOM_STATE
    )

    model = train_untuned(X_train, y_train)

    metrics, cm = evaluate(model, X_test, y_test)
    print("\nHeld-out test metrics:")
    print(json.dumps(metrics, indent=2))
    print("Confusion matrix:", cm.tolist())

    importances = pd.Series(
        model.feature_importances_, index=X.columns
    ).sort_values(ascending=False)
    print("\nTop 10 features:")
    print(importances.head(10))

    write_report(metrics, cm, importances, len(y_test))


if __name__ == "__main__":
    main()