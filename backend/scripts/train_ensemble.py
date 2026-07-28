"""
Phase 3.4 — Step 5: RF + XGBoost ensemble (soft voting).
 
Uses:
  - RandomForestClassifier with the exact Phase 3.3 baseline config
    (n_estimators=200, random_state=42, n_jobs=-1)
  - XGBClassifier with the exact best params found by tune_xgboost.py
    (hardcoded below -- copy these from your own tuning run's printed
    "Best params" if they differ from what's baked in here)
 
Same stratified 80/20 holdout split (random_state=42) as every prior 3.4
script, so the four-way comparison (RF / XGB untuned / XGB tuned / Ensemble)
is apples-to-apples.
 
Container path:
  host:      backend/scripts/train_ensemble.py
  container: scripts/train_ensemble.py
 
Run inside the api container:
  docker compose exec api python scripts/train_ensemble.py
"""
 
import json
from pathlib import Path
 
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
REPORT_PATH = DATA_DIR / "phase3_4_ensemble_results.md"
 
RANDOM_STATE = 42
TEST_SIZE = 0.20
 
# Copied directly from tune_xgboost.py's "Best params" output.
# If you re-run tuning and get different params, update these to match.
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
 
# Prior results, for the four-way comparison table
RF_BASELINE = {
    "accuracy": 0.9712, "precision": 0.9821, "recall": 0.9600,
    "f1": 0.9709, "roc_auc": 0.9980,
}
XGB_UNTUNED = {
    "accuracy": 0.9775, "precision": 0.9728, "recall": 0.9825,
    "f1": 0.9776, "roc_auc": 0.9985,
}
XGB_TUNED = {
    "accuracy": 0.9800, "precision": 0.9824, "recall": 0.9775,
    "f1": 0.9799, "roc_auc": 0.9982,
}
 
 
def load_data():
    X = pd.read_csv(FEATURES_PATH)
    y = pd.read_csv(LABELS_PATH).squeeze("columns")
    return X, y
 
 
def build_ensemble():
    rf = RandomForestClassifier(
        n_estimators=200, random_state=RANDOM_STATE, n_jobs=-1
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
 
 
def write_report(metrics, cm):
    lines = []
    lines.append("# Phase 3.4 — RF + XGBoost Soft-Voting Ensemble Results\n")
    lines.append("## Four-way comparison (held-out test set, n=800)\n")
    lines.append("| Metric | RF (3.3) | XGB untuned (3.4-1) | XGB tuned (3.4-3) | Ensemble (3.4-5) |")
    lines.append("|---|---|---|---|---|")
    for k in metrics:
        lines.append(
            f"| {k} | {RF_BASELINE[k]:.4f} | {XGB_UNTUNED[k]:.4f} | "
            f"{XGB_TUNED[k]:.4f} | {metrics[k]:.4f} |"
        )
    lines.append("")
    lines.append(f"Confusion matrix (ensemble): `{cm.tolist()}`\n")
 
    best_f1 = max(
        [("RF", RF_BASELINE["f1"]), ("XGB untuned", XGB_UNTUNED["f1"]),
         ("XGB tuned", XGB_TUNED["f1"]), ("Ensemble", metrics["f1"])],
        key=lambda x: x[1],
    )
    lines.append(f"**Best F1 of the four: {best_f1[0]} ({best_f1[1]:.4f})**\n")
    lines.append(
        "Decision rule per handoff: only adopt the ensemble for Phase 3.6 if it "
        "meaningfully beats the better of RF/tuned-XGB alone. A tie or marginal "
        "gain on an 800-row test set is not meaningful -- prefer the simpler "
        "single model (tuned XGBoost) in that case.\n"
    )
 
    REPORT_PATH.write_text("\n".join(lines), encoding="utf-8")
    print(f"Report written to {REPORT_PATH}")
 
 
def main():
    X, y = load_data()
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=TEST_SIZE, stratify=y, random_state=RANDOM_STATE
    )
 
    ensemble = build_ensemble()
    ensemble.fit(X_train, y_train)
 
    metrics, cm = evaluate(ensemble, X_test, y_test)
    print(json.dumps(metrics, indent=2))
    print("Confusion matrix:", cm.tolist())
 
    write_report(metrics, cm)
 
 
if __name__ == "__main__":
    main()
 