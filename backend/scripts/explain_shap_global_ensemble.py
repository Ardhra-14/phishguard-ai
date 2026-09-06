"""
Phase 3.5 — SHAP Explainability (Global), ensemble-aware version.

Adapted after this session's decision to adopt the RF+XGBoost soft-voting
ensemble as the final model (see phase3_4_ensemble_results.md and the
"ensemble_adoption_note" in xgboost_phishing_model.meta.json) instead of
tuned XGBoost alone.

shap.TreeExplainer does not work directly on a sklearn VotingClassifier --
it expects a single tree-ensemble object, not a heterogeneous wrapper
around two different model types. Rather than force a single combined SHAP
value across models whose outputs live in different spaces (XGBoost's raw
TreeExplainer output is log-odds/margin space; RandomForest's is
probability space -- naively averaging them would mix units and produce a
misleading number), this script explains each component separately with
its own exact TreeExplainer, and reports them side by side. Since the
ensemble uses soft voting with equal weight on both components, the two
rankings together give a complete, honest picture of what's driving the
final prediction, without a spurious "combined" number that doesn't
actually correspond to any real computation the ensemble performs.

Run:
    docker compose exec api python scripts/explain_shap_global_ensemble.py
"""

import json
import joblib
import numpy as np
import pandas as pd
import shap
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split

MODEL_PATH = "ml/models/xgboost_phishing_model.joblib"
META_PATH = "ml/models/xgboost_phishing_model.meta.json"
FEATURES_PATH = "data/training_features.csv"
LABELS_PATH = "data/training_labels.csv"

OUT_RF_BAR = "data/phase3_5_shap_rf_bar.png"
OUT_XGB_BAR = "data/phase3_5_shap_xgb_bar.png"
OUT_REPORT = "data/phase3_5_shap_global_results.md"
OUT_SHAP_VALUES = "ml/models/shap_values_test.joblib"

RANDOM_STATE = 42
TEST_SIZE = 0.2


def _extract_class1_shap(shap_values):
    """Normalize shap_values() output across shap-version shape conventions
    to a single (n_samples, n_features) array for the positive class."""
    if isinstance(shap_values, list):
        # older convention: list of per-class arrays
        return shap_values[1]
    arr = np.asarray(shap_values)
    if arr.ndim == 3:
        # newer convention: (n_samples, n_features, n_classes)
        return arr[:, :, 1]
    return arr  # already (n_samples, n_features), e.g. XGBoost binary


def main():
    print("Loading ensemble model + metadata...")
    model = joblib.load(MODEL_PATH)
    with open(META_PATH) as f:
        meta = json.load(f)
    feature_order = meta["feature_columns_in_order"]

    rf_model = model.named_estimators_["rf"]
    xgb_model = model.named_estimators_["xgb"]

    print("Loading features/labels and recreating the 3.3/3.4 split...")
    X = pd.read_csv(FEATURES_PATH)[feature_order]
    y = pd.read_csv(LABELS_PATH).squeeze()

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=y
    )
    print(f"Test set: {X_test.shape[0]} rows x {X_test.shape[1]} cols")

    print("Explaining RandomForest component (TreeExplainer)...")
    rf_explainer = shap.TreeExplainer(rf_model, feature_perturbation="tree_path_dependent")
    rf_shap_raw = rf_explainer.shap_values(X_test)
    rf_shap = _extract_class1_shap(rf_shap_raw)

    print("Explaining XGBoost component (TreeExplainer)...")
    xgb_explainer = shap.TreeExplainer(xgb_model, feature_perturbation="tree_path_dependent")
    xgb_shap_raw = xgb_explainer.shap_values(X_test)
    xgb_shap = _extract_class1_shap(xgb_shap_raw)

    rf_ranking = pd.Series(np.abs(rf_shap).mean(axis=0), index=feature_order).sort_values(ascending=False)
    xgb_ranking = pd.Series(np.abs(xgb_shap).mean(axis=0), index=feature_order).sort_values(ascending=False)

    print("Saving bar plots...")
    plt.figure()
    shap.summary_plot(rf_shap, X_test, plot_type="bar", show=False)
    plt.title("RandomForest component (probability space)")
    plt.tight_layout()
    plt.savefig(OUT_RF_BAR, dpi=150)
    plt.close()

    plt.figure()
    shap.summary_plot(xgb_shap, X_test, plot_type="bar", show=False)
    plt.title("XGBoost component (margin/log-odds space)")
    plt.tight_layout()
    plt.savefig(OUT_XGB_BAR, dpi=150)
    plt.close()

    print("Saving raw SHAP values for reuse...")
    joblib.dump(
        {
            "rf_shap_values": rf_shap,
            "xgb_shap_values": xgb_shap,
            "rf_expected_value": rf_explainer.expected_value,
            "xgb_expected_value": xgb_explainer.expected_value,
            "feature_order": feature_order,
            "test_index": X_test.index.tolist(),
        },
        OUT_SHAP_VALUES,
    )

    print("Writing report...")
    top_n = 15
    lines = [
        "# Phase 3.5 — SHAP Global Explainability Results (Ensemble)\n",
        f"Model: RF + XGBoost soft-voting ensemble. n_test={X_test.shape[0]}, "
        f"random_state={RANDOM_STATE}.\n",
        "Explained component-wise (TreeExplainer on each of RF and XGBoost "
        "separately) rather than as a single combined value, since the two "
        "models' raw SHAP outputs live in different spaces (RF: probability, "
        "XGBoost: margin/log-odds) and naively averaging them would be "
        "mathematically invalid. Both components contribute equally to the "
        "final soft-voted prediction.\n",
        f"## Top {top_n} features — RandomForest component (mean |SHAP|, probability space)\n",
        "| Rank | Feature | Mean |SHAP| |",
        "|---|---|---|",
    ]
    for i, (feat, val) in enumerate(rf_ranking.head(top_n).items(), start=1):
        lines.append(f"| {i} | {feat} | {val:.4f} |")

    lines += [
        "",
        f"## Top {top_n} features — XGBoost component (mean |SHAP|, margin space)\n",
        "| Rank | Feature | Mean |SHAP| |",
        "|---|---|---|",
    ]
    for i, (feat, val) in enumerate(xgb_ranking.head(top_n).items(), start=1):
        lines.append(f"| {i} | {feat} | {val:.4f} |")

    lines.append(
        "\n_path_length should no longer dominate either ranking after the "
        "trailing-slash normalization fix -- see phase3_5_path_length_check.md "
        "for the investigation that led here. Compare against each model's "
        "native feature_importances_ from phase3_4_baseline_results.md / "
        "phase3_4_tuned_results.md for a sanity check._\n"
    )

    with open(OUT_REPORT, "w") as f:
        f.write("\n".join(lines))

    print("\nTop 10 by mean |SHAP| -- RandomForest:")
    print(rf_ranking.head(10))
    print("\nTop 10 by mean |SHAP| -- XGBoost:")
    print(xgb_ranking.head(10))
    print(f"\nWrote: {OUT_RF_BAR}, {OUT_XGB_BAR}, {OUT_REPORT}, {OUT_SHAP_VALUES}")


if __name__ == "__main__":
    main()