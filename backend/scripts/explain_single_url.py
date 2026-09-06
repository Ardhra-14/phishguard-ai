"""
Phase 3.5 — Local (per-prediction) SHAP explainability.

Builds both component explainers ONCE (cheap, no background dataset needed
thanks to tree_path_dependent -- see phase3_5_shap_global_results.md), then
exposes explain_single_row(feature_row) for Phase 3.6's scan.py to call
per incoming URL. Component-wise (RF + XGBoost separately), same reasoning
as the global explainability script: the two models' raw SHAP values live
in different spaces (RF: probability, XGBoost: margin/log-odds), so they're
reported side by side rather than forced into one invalid combined number.

This script demonstrates the function against 3 example rows from the
existing test set (highest-confidence phishing, highest-confidence legit,
and a boundary case near 0.5) so the output can be sanity-checked before
Phase 3.6 depends on it.

For Phase 3.6 integration: call build_explainers() once at API startup
(cheap -- TreeExplainer construction from an already-fitted model is fast),
then call explain_single_row(row, rf_explainer, xgb_explainer, ...) per
scanned URL. Do NOT rebuild explainers per-request.

Run:
    docker compose exec api python scripts/explain_single_url.py
"""

import json
import joblib
import numpy as np
import pandas as pd
import shap
from sklearn.model_selection import train_test_split

MODEL_PATH = "ml/models/xgboost_phishing_model.joblib"
META_PATH = "ml/models/xgboost_phishing_model.meta.json"
FEATURES_PATH = "data/training_features.csv"
LABELS_PATH = "data/training_labels.csv"
OUT_REPORT = "data/phase3_5_local_explainability_examples.md"

RANDOM_STATE = 42
TEST_SIZE = 0.2
TOP_N = 8


def _extract_class1_shap(shap_values):
    if isinstance(shap_values, list):
        return shap_values[1]
    arr = np.asarray(shap_values)
    if arr.ndim == 3:
        return arr[:, :, 1]
    if arr.ndim == 2:
        return arr
    return arr.reshape(1, -1)  # single-row case


def build_explainers(model):
    """Call once (e.g. at API startup for Phase 3.6). Cheap -- no
    background dataset needed, tree_path_dependent uses the model's own
    tree structure."""
    rf_model = model.named_estimators_["rf"]
    xgb_model = model.named_estimators_["xgb"]
    rf_explainer = shap.TreeExplainer(rf_model, feature_perturbation="tree_path_dependent")
    xgb_explainer = shap.TreeExplainer(xgb_model, feature_perturbation="tree_path_dependent")
    return rf_explainer, xgb_explainer


def explain_single_row(row_df, rf_explainer, xgb_explainer, feature_order, top_n=TOP_N):
    """row_df: a single-row DataFrame with columns in feature_order.
    Returns a dict ready to serialize for an API response / report."""
    rf_shap = _extract_class1_shap(rf_explainer.shap_values(row_df))[0]
    xgb_shap = _extract_class1_shap(xgb_explainer.shap_values(row_df))[0]

    rf_series = pd.Series(rf_shap, index=feature_order).sort_values(key=abs, ascending=False)
    xgb_series = pd.Series(xgb_shap, index=feature_order).sort_values(key=abs, ascending=False)

    return {
        "random_forest": {
            "base_value": float(np.asarray(rf_explainer.expected_value).reshape(-1)[-1]),
            "top_contributions": [
                {"feature": f, "shap_value": float(v), "feature_value": float(row_df[f].iloc[0])}
                for f, v in rf_series.head(top_n).items()
            ],
        },
        "xgboost": {
            "base_value": float(np.asarray(xgb_explainer.expected_value).reshape(-1)[-1]),
            "top_contributions": [
                {"feature": f, "shap_value": float(v), "feature_value": float(row_df[f].iloc[0])}
                for f, v in xgb_series.head(top_n).items()
            ],
        },
    }


def _format_example(label, row, proba, explanation):
    lines = [f"### {label} (predicted P(phishing) = {proba:.4f})\n"]
    lines.append("**RandomForest component** (probability space, "
                  f"base value {explanation['random_forest']['base_value']:.4f}):\n")
    lines.append("| Feature | Value | SHAP contribution |")
    lines.append("|---|---|---|")
    for c in explanation["random_forest"]["top_contributions"]:
        lines.append(f"| {c['feature']} | {c['feature_value']:.3g} | {c['shap_value']:+.4f} |")
    lines.append("")
    lines.append("**XGBoost component** (margin/log-odds space, "
                  f"base value {explanation['xgboost']['base_value']:.4f}):\n")
    lines.append("| Feature | Value | SHAP contribution |")
    lines.append("|---|---|---|")
    for c in explanation["xgboost"]["top_contributions"]:
        lines.append(f"| {c['feature']} | {c['feature_value']:.3g} | {c['shap_value']:+.4f} |")
    lines.append("")
    return "\n".join(lines)


def main():
    print("Loading ensemble model + metadata...")
    model = joblib.load(MODEL_PATH)
    with open(META_PATH) as f:
        meta = json.load(f)
    feature_order = meta["feature_columns_in_order"]

    X = pd.read_csv(FEATURES_PATH)[feature_order]
    y = pd.read_csv(LABELS_PATH).squeeze()
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=y
    )

    print("Building explainers (once)...")
    rf_explainer, xgb_explainer = build_explainers(model)

    proba = model.predict_proba(X_test)[:, 1]
    idx_phish = int(np.argmax(proba))
    idx_legit = int(np.argmin(proba))
    idx_boundary = int(np.argmin(np.abs(proba - 0.5)))

    examples = [
        ("Highest-confidence PHISHING prediction", idx_phish),
        ("Highest-confidence LEGIT prediction", idx_legit),
        ("Boundary case (closest to 0.5)", idx_boundary),
    ]

    report_sections = ["# Phase 3.5 — Local Explainability Examples\n",
                        "Three example rows from the held-out test set, explained via "
                        "explain_single_row(). Demonstrates the function Phase 3.6 should "
                        "call per scanned URL.\n"]

    for label, idx in examples:
        row = X_test.iloc[[idx]]
        p = proba[idx]
        true_label = "phishing" if y_test.iloc[idx] == 1 else "legit"
        print(f"\n=== {label} (true label: {true_label}, P(phishing)={p:.4f}) ===")
        explanation = explain_single_row(row, rf_explainer, xgb_explainer, feature_order)
        print(json.dumps(explanation, indent=2))
        report_sections.append(_format_example(f"{label} (true label: {true_label})", row, p, explanation))

    with open(OUT_REPORT, "w") as f:
        f.write("\n".join(report_sections))
    print(f"\nWrote {OUT_REPORT}")


if __name__ == "__main__":
    main()