"""
Phase 3.3 — Random Forest baseline.

Reads the Phase 3.2 outputs (training_features.csv, training_labels.csv),
does a stratified train/test split, trains a plain RandomForestClassifier
with no hyperparameter tuning, and reports accuracy/precision/recall/F1/ROC-AUC
plus a confusion matrix and a feature-importance sanity check.

This is the baseline to beat in Phase 3.4 (XGBoost + tuning). No model is
saved to disk here — persistence is Phase 3.7.

Usage (inside the api container):
    docker compose exec api python scripts/train_random_forest_baseline.py

Note: the compose bind mount is `./backend:/app`, so inside the container the
repo's backend/ IS /app — paths are relative to that (scripts/..., data/...),
NOT backend/scripts/... . Same convention as analyze_training_dataset.py /
preprocess_training_data.py already running fine in this container.
"""

import json
from pathlib import Path

import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
    classification_report,
)

DATA_DIR = Path("data")
FEATURES_PATH = DATA_DIR / "training_features.csv"
LABELS_PATH = DATA_DIR / "training_labels.csv"
REPORT_PATH = DATA_DIR / "phase3_3_baseline_results.md"

RANDOM_STATE = 42
TEST_SIZE = 0.20
N_TOP_FEATURES = 15


def load_data():
    X = pd.read_csv(FEATURES_PATH)
    y = pd.read_csv(LABELS_PATH)["label"]

    if len(X) != len(y):
        raise ValueError(
            f"Row count mismatch: features has {len(X)} rows, labels has {len(y)} rows"
        )
    if X.isnull().any().any():
        raise ValueError(
            "training_features.csv has nulls — Phase 3.2 preprocessing script "
            "should have hard-exited before writing a file with nulls. Re-check that step."
        )

    return X, y


def split_data(X, y):
    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=TEST_SIZE,
        random_state=RANDOM_STATE,
        stratify=y,
    )
    return X_train, X_test, y_train, y_test


def train_model(X_train, y_train):
    model = RandomForestClassifier(
        n_estimators=200,
        random_state=RANDOM_STATE,
        n_jobs=-1,
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
    report = classification_report(y_test, y_pred, target_names=["legit (0)", "phishing (1)"])

    return metrics, cm, report


def feature_importance(model, feature_names):
    importances = pd.Series(model.feature_importances_, index=feature_names)
    return importances.sort_values(ascending=False).head(N_TOP_FEATURES)


def write_report(metrics, cm, report, top_features, n_train, n_test):
    lines = []
    lines.append("# Phase 3.3 — Random Forest Baseline Results\n")
    lines.append(f"Train rows: {n_train} | Test rows: {n_test} "
                  f"(stratified {int((1-TEST_SIZE)*100)}/{int(TEST_SIZE*100)} split, "
                  f"random_state={RANDOM_STATE})\n")

    lines.append("## Metrics (test set)\n")
    lines.append("| Metric | Value |")
    lines.append("|---|---|")
    for k, v in metrics.items():
        lines.append(f"| {k} | {v:.4f} |")
    lines.append("")

    lines.append("## Confusion Matrix\n")
    lines.append("Rows = actual, Columns = predicted. Order: [legit (0), phishing (1)]\n")
    lines.append("```")
    lines.append(str(cm))
    lines.append("```\n")

    lines.append("## Classification Report\n")
    lines.append("```")
    lines.append(report)
    lines.append("```\n")

    lines.append(f"## Top {N_TOP_FEATURES} Features by Importance\n")
    lines.append("| Feature | Importance |")
    lines.append("|---|---|")
    for name, val in top_features.items():
        lines.append(f"| {name} | {val:.4f} |")
    lines.append("")

    REPORT_PATH.write_text("\n".join(lines), encoding="utf-8")


def main():
    print(f"Loading {FEATURES_PATH} and {LABELS_PATH} ...")
    X, y = load_data()
    print(f"Loaded {len(X)} rows x {X.shape[1]} feature columns. "
          f"Label balance: {y.value_counts().to_dict()}")

    X_train, X_test, y_train, y_test = split_data(X, y)
    print(f"Split: {len(X_train)} train / {len(X_test)} test "
          f"(train balance: {y_train.value_counts().to_dict()}, "
          f"test balance: {y_test.value_counts().to_dict()})")

    print("Training RandomForestClassifier(n_estimators=200, no tuning) ...")
    model = train_model(X_train, y_train)

    print("Evaluating on held-out test set ...")
    metrics, cm, report = evaluate(model, X_test, y_test)

    print("\n=== Metrics ===")
    for k, v in metrics.items():
        print(f"{k:>10}: {v:.4f}")

    print("\n=== Confusion Matrix ===")
    print("(rows=actual, cols=predicted, order=[legit(0), phishing(1)])")
    print(cm)

    print("\n=== Classification Report ===")
    print(report)

    top_features = feature_importance(model, X.columns)
    print(f"\n=== Top {N_TOP_FEATURES} Features by Importance ===")
    print(top_features.to_string())

    write_report(metrics, cm, report, top_features, len(X_train), len(X_test))
    print(f"\nWrote report to {REPORT_PATH}")


if __name__ == "__main__":
    main()
