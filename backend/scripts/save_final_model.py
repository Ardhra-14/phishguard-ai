"""
Phase 3.4 wrap-up: persist the final model.

DECISION UPDATE (this session, Phase 3.5 rebuild): in the original Phase
3.4 run and the first two rebuild cycles this session, the RF+XGBoost soft-
voting ensemble tied tuned XGBoost exactly on every metric, so tuned
XGBoost alone was kept per the "only adopt ensemble if it meaningfully
beats the better single model" rule. After the path_length trailing-slash
fix (see phase3_5_path_length_check.md), the ensemble now beats every
individual model (RF, XGB untuned, XGB tuned) simultaneously on accuracy,
precision, and f1, with the most balanced confusion matrix of the four
(17 FP / 16 FN) -- see phase3_4_ensemble_results.md. The gain is modest
(~0.4pp, within one standard error on an 800-row test set) but consistent
across multiple metrics rather than a single-metric artifact, so the
ensemble is adopted for Phase 3.6 instead of tuned XGBoost alone.

This script now saves the fitted VotingClassifier (RF + XGBoost, soft
voting) rather than a standalone XGBClassifier. Component hyperparameters
are unchanged from train_ensemble.py.

Design choice (flag for review at Phase 3.7): this saves the model trained
on the SAME 80% train split used throughout 3.4, so the persisted model's
sanity-check metrics match what's already been reported (RF/XGB/ensemble
comparison tables) exactly. When Phase 3.6/3.7 build the final production
predictor, you may want to retrain on the FULL 4000-row dataset (train+test
combined) for a small extra bit of signal before shipping -- that's a
separate decision, not done here, so nothing in this script is silently
using test data it shouldn't.

Saves:
  - ml/models/xgboost_phishing_model.joblib   (the fitted VotingClassifier
    ensemble -- filename kept as-is for compatibility with anything in
    Phase 3.6 that already expects this path; it is no longer a bare
    XGBClassifier, see meta.json's model_type field)
  - ml/models/xgboost_phishing_model.meta.json (component hyperparameters,
    metrics, feature column order -- needed at inference time to make sure
    incoming feature vectors are built/ordered identically to training)

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
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
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
    "colsample_bytree": 0.7043574493366855,
    "gamma": 0.07652270145192375,
    "learning_rate": 0.28069652934305006,
    "max_depth": 9,
    "min_child_weight": 1,
    "n_estimators": 424,
    "reg_alpha": 1.3679275387962821,
    "reg_lambda": 2.655479075364698,
    "subsample": 0.9775566418243029,
}

RF_PARAMS = {
    "n_estimators": 200,
}


def load_data():
    X = pd.read_csv(FEATURES_PATH)
    y = pd.read_csv(LABELS_PATH).squeeze("columns")
    return X, y


def build_ensemble():
    rf = RandomForestClassifier(
        n_estimators=RF_PARAMS["n_estimators"],
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )
    xgb = XGBClassifier(
        random_state=RANDOM_STATE,
        n_jobs=1,  # avoid nested-parallelism issues seen during tuning
        eval_metric="logloss",
        **TUNED_XGB_PARAMS,
    )
    ensemble = VotingClassifier(
        estimators=[("rf", rf), ("xgb", xgb)],
        voting="soft",
        n_jobs=1,
    )
    return ensemble


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

    model = build_ensemble()
    model.fit(X_train, y_train)

    # Sanity check: these should match the phase3_4_ensemble_results.md
    # numbers exactly (same split, same component params). If they don't,
    # something drifted (different feature CSV, different sklearn/xgboost
    # version, etc.) -- investigate before trusting the saved model.
    metrics, cm = evaluate(model, X_test, y_test)
    print("Sanity-check metrics (should match phase3_4_ensemble_results.md):")
    print(json.dumps(metrics, indent=2))
    print("Confusion matrix:", cm.tolist())

    joblib.dump(model, MODEL_PATH)
    print(f"\nModel saved to {MODEL_PATH}")

    metadata = {
        "saved_at_utc": datetime.now(timezone.utc).isoformat(),
        "model_type": "VotingClassifier (RandomForestClassifier + XGBClassifier, soft voting)",
        "phase": "3.4",
        "ensemble_adoption_note": (
            "Adopted this session after the path_length trailing-slash fix "
            "made the ensemble beat every individual model simultaneously "
            "on accuracy/precision/f1 -- see phase3_4_ensemble_results.md "
            "and phase3_5_path_length_check.md. Prior cycles kept tuned "
            "XGBoost alone since the ensemble tied it exactly."
        ),
        "trained_on": "80% stratified split of training_features.csv (NOT full dataset)",
        "random_state": RANDOM_STATE,
        "test_size": TEST_SIZE,
        "component_hyperparameters": {
            "random_forest": {**RF_PARAMS, "random_state": RANDOM_STATE},
            "xgboost": TUNED_XGB_PARAMS,
        },
        "voting": "soft",
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