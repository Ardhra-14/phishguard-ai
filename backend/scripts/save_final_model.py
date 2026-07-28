"""
Phase 3.4 wrap-up: persist the tuned XGBoost model.

Design choice (flag for review at Phase 3.7): this saves the model trained
on the SAME 80% train split used throughout 3.4, so the persisted model's
sanity-check metrics match what's already been reported (RF/XGB/ensemble
comparison tables) exactly. When Phase 3.6/3.7 build the final production
predictor, you may want to retrain on the FULL 4000-row dataset (train+test
combined) for a small extra bit of signal before shipping -- that's a
separate decision, not done here, so nothing in this script is silently
using test data it shouldn't.

Saves:
  - ml/models/xgboost_phishing_model.joblib   (the fitted model)
  - ml/models/xgboost_phishing_model.meta.json (params, metrics, feature
    column order -- needed at inference time to make sure incoming feature
    vectors are built/ordered identically to training)

Container path:
  host:      backend/scripts/save_final_model.py
  container: scripts/save_final_model.py

Run inside the api container:
  docker compose exec api python scripts/save_final_model.py
"""

import json
from datetime import datetime, timezone
from pathlib import Path

import joblib
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

MODEL_DIR = Path("ml/models")
MODEL_PATH = MODEL_DIR / "xgboost_phishing_model.joblib"
META_PATH = MODEL_DIR / "xgboost_phishing_model.meta.json"

RANDOM_STATE = 42
TEST_SIZE = 0.20

# Same best params as tune_xgboost.py / train_ensemble.py
TUNED_XGB_PARAMS = {
    "colsample_bytree": 0.610167650697638,
    "gamma": 0.5394571349665223,
    "learning_rate": 0.019114463849152934,
    "max_depth": 8,
    "min_child_weight": 1,
    "n_estimators": 663,
    "reg_alpha": 1.1265511439527673,
    "reg_lambda": 2.9343063024914464,
    "subsample": 0.6557325817623503,
}


def load_data():
    X = pd.read_csv(FEATURES_PATH)
    y = pd.read_csv(LABELS_PATH).squeeze("columns")
    return X, y


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


def main():
    MODEL_DIR.mkdir(parents=True, exist_ok=True)

    X, y = load_data()
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=TEST_SIZE, stratify=y, random_state=RANDOM_STATE
    )

    model = XGBClassifier(
        random_state=RANDOM_STATE,
        n_jobs=-1,
        eval_metric="logloss",
        **TUNED_XGB_PARAMS,
    )
    model.fit(X_train, y_train)

    # Sanity check: these should match the phase3_4_tuned_results.md numbers
    # exactly (same split, same params). If they don't, something drifted
    # (different feature CSV, different sklearn/xgboost version, etc.) --
    # investigate before trusting the saved model.
    metrics, cm = evaluate(model, X_test, y_test)
    print("Sanity-check metrics (should match phase3_4_tuned_results.md):")
    print(json.dumps(metrics, indent=2))
    print("Confusion matrix:", cm.tolist())

    joblib.dump(model, MODEL_PATH)
    print(f"\nModel saved to {MODEL_PATH}")

    metadata = {
        "saved_at_utc": datetime.now(timezone.utc).isoformat(),
        "model_type": "XGBClassifier",
        "phase": "3.4",
        "trained_on": "80% stratified split of training_features.csv (NOT full dataset)",
        "random_state": RANDOM_STATE,
        "test_size": TEST_SIZE,
        "hyperparameters": TUNED_XGB_PARAMS,
        "feature_columns_in_order": list(X.columns),
        "n_features": X.shape[1],
        "sanity_check_metrics": metrics,
        "sanity_check_confusion_matrix": cm.tolist(),
        "requires_for_inference": (
            "data/preprocessing_artifacts.json (frequency maps + ssl_issuer "
            "top-10 list from Phase 3.2) to encode a single incoming URL "
            "identically to how this training data was encoded."
        ),
    }
    META_PATH.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    print(f"Metadata saved to {META_PATH}")


if __name__ == "__main__":
    main()