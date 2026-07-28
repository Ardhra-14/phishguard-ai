"""
Phase 3.4 — Step 3: XGBoost hyperparameter tuning via RandomizedSearchCV.

Same stratified 80/20 holdout split as 3.3/3.4-step1 (random_state=42) so the
final held-out numbers stay comparable. Tuning itself uses 5-fold stratified
CV on the training split only -- the test split is never touched until the
very end, so we get an honest, non-leaked estimate.

Container path:
  host:      backend/scripts/tune_xgboost.py
  container: scripts/tune_xgboost.py

Run inside the api container:
  docker compose exec api python scripts/tune_xgboost.py
"""

import json
from pathlib import Path

import numpy as np
import pandas as pd
from scipy.stats import randint, uniform
from sklearn.model_selection import train_test_split, RandomizedSearchCV, StratifiedKFold
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
REPORT_PATH = DATA_DIR / "phase3_4_tuned_results.md"
SEARCH_LOG_PATH = DATA_DIR / "phase3_4_search_log.csv"

RANDOM_STATE = 42
TEST_SIZE = 0.20
N_ITER = 50          # number of random param combos to try
CV_FOLDS = 5
SCORING = "roc_auc"  # optimize the same metric we report as headline AUC

PARAM_DISTRIBUTIONS = {
    "n_estimators": randint(100, 800),
    "max_depth": randint(2, 10),
    "learning_rate": uniform(0.01, 0.29),       # 0.01 - 0.30
    "subsample": uniform(0.6, 0.4),             # 0.6 - 1.0
    "colsample_bytree": uniform(0.6, 0.4),      # 0.6 - 1.0
    "min_child_weight": randint(1, 10),
    "gamma": uniform(0, 5),
    "reg_alpha": uniform(0, 2),
    "reg_lambda": uniform(0.5, 3.5),            # 0.5 - 4.0
}

# Baselines to compare against in the final report
RF_BASELINE = {
    "accuracy": 0.9712, "precision": 0.9821, "recall": 0.9600,
    "f1": 0.9709, "roc_auc": 0.9980,
}
XGB_UNTUNED_BASELINE = {
    "accuracy": 0.9775, "precision": 0.9728, "recall": 0.9825,
    "f1": 0.9776, "roc_auc": 0.9985,
}


def load_data():
    X = pd.read_csv(FEATURES_PATH)
    y = pd.read_csv(LABELS_PATH).squeeze("columns")
    return X, y


def run_search(X_train, y_train):
    base_model = XGBClassifier(
        random_state=RANDOM_STATE,
        n_jobs=-1,
        eval_metric="logloss",
    )
    cv = StratifiedKFold(n_splits=CV_FOLDS, shuffle=True, random_state=RANDOM_STATE)

    search = RandomizedSearchCV(
        estimator=base_model,
        param_distributions=PARAM_DISTRIBUTIONS,
        n_iter=N_ITER,
        scoring=SCORING,
        cv=cv,
        random_state=RANDOM_STATE,
        n_jobs=-1,
        verbose=1,
        refit=True,
    )
    search.fit(X_train, y_train)
    return search


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


def write_report(best_params, cv_best_score, metrics, cm, importances, n_test):
    lines = []
    lines.append("# Phase 3.4 — XGBoost Tuned Results (Step 3: RandomizedSearchCV)\n")
    lines.append(f"Search: {N_ITER} iterations, {CV_FOLDS}-fold stratified CV, scoring={SCORING}\n")
    lines.append(f"Best CV {SCORING}: {cv_best_score:.4f}\n")
    lines.append("## Best hyperparameters\n")
    lines.append("```json")
    lines.append(json.dumps(best_params, indent=2, default=float))
    lines.append("```\n")
    lines.append(f"Held-out test set: n={n_test}\n")
    lines.append("## Three-way comparison (held-out test set)\n")
    lines.append("| Metric | RF (3.3) | XGB untuned (3.4-1) | XGB tuned (3.4-3) | Delta vs untuned |")
    lines.append("|---|---|---|---|---|")
    for k in metrics:
        delta = metrics[k] - XGB_UNTUNED_BASELINE[k]
        lines.append(
            f"| {k} | {RF_BASELINE[k]:.4f} | {XGB_UNTUNED_BASELINE[k]:.4f} | "
            f"{metrics[k]:.4f} | {delta:+.4f} |"
        )
    lines.append("")
    lines.append(f"Confusion matrix (tuned): `{cm.tolist()}`\n")
    lines.append("## Top 10 features by importance (tuned model)\n")
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

    search = run_search(X_train, y_train)

    # Save the full search history for later inspection (which regions of
    # hyperparameter space were tried, in case Step 3 needs a follow-up pass)
    pd.DataFrame(search.cv_results_).sort_values(
        "rank_test_score"
    ).to_csv(SEARCH_LOG_PATH, index=False)
    print(f"Full search log written to {SEARCH_LOG_PATH}")

    best_model = search.best_estimator_
    print(f"\nBest CV {SCORING}: {search.best_score_:.4f}")
    print("Best params:", json.dumps(search.best_params_, indent=2, default=float))

    metrics, cm = evaluate(best_model, X_test, y_test)
    print("\nHeld-out test metrics:")
    print(json.dumps(metrics, indent=2))
    print("Confusion matrix:", cm.tolist())

    importances = pd.Series(
        best_model.feature_importances_, index=X.columns
    ).sort_values(ascending=False)
    print("\nTop 10 features:")
    print(importances.head(10))

    write_report(
        search.best_params_, search.best_score_, metrics, cm, importances, len(y_test)
    )


if __name__ == "__main__":
    main()