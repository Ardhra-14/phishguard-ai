"""
Predictor - Phase 3.6 real ensemble wiring.

Loads the trained VotingClassifier (RandomForest + XGBoost, soft voting)
and encodes incoming feature dicts (from features/pipeline.py's
FeaturePipeline.extract()) into the exact 54-column order the model was
trained on, then returns a verdict + score + per-request SHAP explanation.

The predict(features: dict) -> dict interface matches the Phase 3 placeholder
this file replaces, so scan.py's call site doesn't need to change shape -
it should import the module-level `predictor` singleton below (NOT the
`Predictor` class) so the model / preprocessing artifacts / SHAP explainers
are loaded exactly once, at import time, instead of once per request.

── Reconstruction note ──────────────────────────────────────────────────────
This file reconstructs the real Phase 3.6 implementation from its handoff
docs (PhishGuard_AI_Phase3_6_Summary.md / Phase3_7_Handoff.md) after the
original session's version of this file was found to be uncommitted /
never pushed to origin/main. The behavioral decisions below are pulled
directly from those docs; anywhere the docs didn't fully specify an
implementation detail (e.g. exact SHAP-label humanization, exact
`confidence` formula), a reasonable choice was made and is called out
inline as [reconstruction choice] so it's easy to find and revisit.

── Documented decisions (read before modifying) ─────────────────────────────
1. Unseen TLD/registrar categories -> frequency 0.0 (judgment call).
2. Missing numerics -> filled with `sentinel_value` (-1) from
   preprocessing_artifacts.json. Missing *booleans* (e.g. ssl_valid is
   None because nothing listened on 443) also fall back to the sentinel,
   not to 0/False, so "no data" stays distinguishable from "checked and
   found false".
3. Verdict thresholds: score >= 70 -> PHISHING, >= 35 -> SUSPICIOUS, else
   SAFE. NOT derived from a calibration curve or precision/recall sweep -
   a reasonable starting point given 0.99 ROC-AUC, but should be replaced
   with real threshold analysis before shipping to CERT-In (Phase 3.7
   open issue #3).
4. Visual score blend: feature_columns_in_order does NOT include
   visual_similarity_score / dom_credential_form_detected (the visual
   module was built after Phase 3.4/3.5 training). A small, capped,
   documented post-hoc score bump (+12 with a detected login form, +6
   without) is applied when visual_similarity_score >= 0.80. Whether this
   is the right call vs. retraining with visual features included is a
   product decision, not something this file settles.
5. registrar/ssl_issuer/closest_brand key names pulled from the features
   dict using best-guess names (whois_registrar, ssl_issuer,
   closest_brand). All three are confirmed real FeaturePipeline output
   keys. `closest_brand` was threaded through in pipeline.py (Phase 3.7
   open issue #2) - but ONLY when brand_clone_flagged is True, not
   whenever analyze_screenshot() returns any argmin match. The first
   pass of this fix surfaced closest_brand unconditionally and broke
   immediately in testing: compare_to_brands() always returns the
   *closest available* reference brand even when the hash distance is
   nowhere near a real match (google.com "matched" HDFC at distance 28,
   nowhere close to CLONE_THRESHOLD=12) - gating on the already-computed,
   already-thresholded brand_clone_flagged fixes this without touching
   CLONE_THRESHOLD or the reference-brand set at all.
6. `category` - no known source anywhere in the docs handed off. Stays
   None with a TODO.
7. SHAP schema flattening - only the RandomForest component's
   top_contributions are surfaced in the flat `shap` list, since RF's
   values are already probability-scale and directly comparable to
   score/confidence. XGBoost's log-odds contributions are computed (and
   available on request) but not included in the response. If both
   models' explanations are wanted, ShapFeature needs a `model: str`
   field added first - that's a schema decision, not one this file can
   make on its own.
"""
import json
import re
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

try:
    import shap
    _SHAP_AVAILABLE = True
except ImportError:  # pragma: no cover - shap should always be installed per requirements.txt
    _SHAP_AVAILABLE = False

_ML_DIR = Path(__file__).resolve().parent
_BACKEND_DIR = _ML_DIR.parent

MODEL_PATH = _ML_DIR / "models" / "xgboost_phishing_model.joblib"
META_PATH = _ML_DIR / "models" / "xgboost_phishing_model.meta.json"
PREPROCESSING_ARTIFACTS_PATH = _BACKEND_DIR / "data" / "preprocessing_artifacts.json"

TOP_N_SHAP = 8

# Feature keys that pass straight through the incoming feature dict into the
# model's input row, unencoded (numeric / already-int-cast booleans).
_PASSTHROUGH_NUMERIC_KEYS = [
    "url_length", "hyphen_count", "dot_count", "digit_count", "entropy",
    "subdomain_depth", "has_https", "is_ip_address", "has_at_symbol",
    "path_length", "query_param_count", "special_char_count",
    "brand_impersonation_score", "brand_matched_count", "brand_keyword_hit_count",
    "brand_typosquat_hit_count", "brand_has_action_word",
    "tld_risk_score", "tld_known",
    "idn_is_homograph", "idn_confusable_count", "idn_risk_score", "idn_punycode_flag",
    "dns_resolves", "dns_a_record_count", "dns_has_aaaa", "dns_has_mx",
    "whois_domain_age_days", "whois_recently_registered", "whois_privacy_protected", "whois_found",
    "ssl_valid", "ssl_self_signed", "ssl_days_until_expiry", "ssl_expired",
    "aggregate_lexical_risk_score",
]

# feature_columns_in_order name -> source feature-dict key for missing-flags
_MISSING_FLAG_SOURCES = {
    "whois_registrar_was_missing": "whois_registrar",
    "whois_domain_age_days_was_missing": "whois_domain_age_days",
    "ssl_days_until_expiry_was_missing": "ssl_days_until_expiry",
    "ssl_issuer_was_missing": "ssl_issuer",
    "ssl_expired_was_missing": "ssl_expired",
}


def _normalize_ssl_issuer(raw: str) -> str:
    """lowercase, strip periods, collapse remaining punctuation/whitespace
    to single underscores. Apostrophes are preserved (so "Let's Encrypt"
    -> "let's_encrypt", matching the trained column name), which is also
    why "DigiCert Inc" and "DigiCert, Inc." both collapse to the same
    "digicert_inc" column - a real, harmless collision documented in the
    Phase 3.6 summary, not a bug."""
    s = raw.lower().replace(".", "")
    s = re.sub(r"[^a-z0-9']+", "_", s)
    s = re.sub(r"_+", "_", s).strip("_")
    return s


def _humanize_feature_name(name: str) -> str:
    """[reconstruction choice] simple title-cased label for the SHAP
    feature list; the docs don't specify a label lookup table, so this is
    a straightforward underscore->space, title-case transform."""
    return name.replace("_", " ").strip().title()


def _extract_class1_shap(shap_values):
    if isinstance(shap_values, list):
        return shap_values[1]
    arr = np.asarray(shap_values)
    if arr.ndim == 3:
        return arr[:, :, 1]
    if arr.ndim == 2:
        return arr
    return arr.reshape(1, -1)


def build_explainers(model):
    """Call once, at import time. Cheap - TreeExplainer construction from
    an already-fitted model doesn't need a background dataset thanks to
    tree_path_dependent."""
    rf_model = model.named_estimators_["rf"]
    xgb_model = model.named_estimators_["xgb"]
    rf_explainer = shap.TreeExplainer(rf_model, feature_perturbation="tree_path_dependent")
    xgb_explainer = shap.TreeExplainer(xgb_model, feature_perturbation="tree_path_dependent")
    return rf_explainer, xgb_explainer


def explain_single_row(row_df, rf_explainer, xgb_explainer, feature_order, top_n=TOP_N_SHAP):
    """row_df: single-row DataFrame with columns in feature_order.
    Returns component-wise SHAP explanations (RF: probability space,
    XGBoost: margin/log-odds space - reported separately, never combined
    into one number, per explain_single_url.py's Phase 3.5 docstring)."""
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


class Predictor:
    """Real trained ensemble. Loads model/meta/preprocessing artifacts and
    builds SHAP explainers once, in __init__ - instantiate this exactly
    once (see the `predictor` singleton at the bottom of this module)."""

    def __init__(self):
        self.model = joblib.load(MODEL_PATH)
        with open(META_PATH) as f:
            self.meta = json.load(f)
        with open(PREPROCESSING_ARTIFACTS_PATH) as f:
            self.preprocessing = json.load(f)

        self.feature_order = self.meta["feature_columns_in_order"]
        self.sentinel = self.preprocessing["sentinel_value"]
        self.tld_freq_map = self.preprocessing["frequency_encoding"]["tld"]
        self.registrar_freq_map = self.preprocessing["frequency_encoding"]["whois_registrar"]
        self.ssl_issuer_top_values = self.preprocessing["ssl_issuer_top_values"]

        # Build the set of known normalized ssl_issuer values -> the exact
        # one-hot column name for each, straight from feature_columns_in_order,
        # so encoding stays correct even if collisions change the count.
        # NOTE: "ssl_issuer_was_missing" also starts with "ssl_issuer_" but is
        # the separate missing-flag column (handled by _MISSING_FLAG_SOURCES),
        # not a one-hot category - it must be excluded here or the one-hot
        # encoder silently clobbers the correct missing-flag value with 0.
        self._ssl_issuer_columns = {
            col for col in self.feature_order
            if col.startswith("ssl_issuer_") and col != "ssl_issuer_was_missing"
        }
        self._ssl_issuer_normalized_to_column = {}
        for raw in self.ssl_issuer_top_values:
            normalized = _normalize_ssl_issuer(raw)
            col = f"ssl_issuer_{normalized}"
            if col in self._ssl_issuer_columns:
                self._ssl_issuer_normalized_to_column[normalized] = col

        self.rf_explainer, self.xgb_explainer = (
            build_explainers(self.model) if _SHAP_AVAILABLE else (None, None)
        )

    # ── encoding ──────────────────────────────────────────────────────────

    def _numeric_or_sentinel(self, features: dict, key: str):
        v = features.get(key)
        if v is None:
            return self.sentinel
        if isinstance(v, bool):
            return int(v)
        return v

    def _encode_ssl_issuer_one_hot(self, ssl_issuer) -> dict:
        """Returns {column_name: 0/1} for every ssl_issuer_* column."""
        row = {col: 0 for col in self._ssl_issuer_columns}
        if ssl_issuer is None:
            row["ssl_issuer_missing"] = 1
            return row
        normalized = _normalize_ssl_issuer(ssl_issuer)
        col = self._ssl_issuer_normalized_to_column.get(normalized)
        if col is not None:
            row[col] = 1
        else:
            row["ssl_issuer_other"] = 1
        return row

    def _encode(self, features: dict) -> pd.DataFrame:
        """Builds the exact 54-column, correctly-ordered single-row
        DataFrame the model expects, from a FeaturePipeline.extract()-style
        feature dict."""
        row = {}

        for key in _PASSTHROUGH_NUMERIC_KEYS:
            row[key] = self._numeric_or_sentinel(features, key)

        for flag_col, source_key in _MISSING_FLAG_SOURCES.items():
            row[flag_col] = int(features.get(source_key) is None)

        row["tld_freq"] = self.tld_freq_map.get(features.get("tld"), 0.0)
        row["whois_registrar_freq"] = self.registrar_freq_map.get(
            features.get("whois_registrar") or "__missing__", 0.0
        )

        row.update(self._encode_ssl_issuer_one_hot(features.get("ssl_issuer")))

        return pd.DataFrame([row], columns=self.feature_order)

    # ── scoring ───────────────────────────────────────────────────────────

    @staticmethod
    def _score_and_verdict(proba_phishing: float) -> tuple[int, str, float]:
        score = min(round(proba_phishing * 100), 100)
        score = max(score, 0)
        if score >= 70:
            verdict = "PHISHING"
        elif score >= 35:
            verdict = "SUSPICIOUS"
        else:
            verdict = "SAFE"
        # [reconstruction choice] confidence = model's raw P(phishing),
        # rounded. Docs specify score/verdict thresholds precisely but not
        # a confidence formula distinct from score; this keeps confidence
        # a direct, unambiguous read of the model's own output.
        confidence = round(float(proba_phishing), 2)
        return score, verdict, confidence

    @staticmethod
    def _apply_visual_adjustment(score: int, visual_similarity_score, has_login_form) -> int:
        """+12/+6 capped post-hoc bump when visual_similarity_score >= 0.80
        (decision #4 above). Never pushes score past 100."""
        if visual_similarity_score is not None and visual_similarity_score >= 0.80:
            bump = 12 if has_login_form else 6
            score = min(score + bump, 100)
        return score

    def _flatten_shap_for_schema(self, explanation: dict) -> list[dict]:
        """Only the RandomForest component is surfaced (decision #7).
        Matches scan.py's ShapFeature schema: feature, label, value,
        shap_value, direction."""
        contributions = explanation.get("random_forest", {}).get("top_contributions", [])
        flattened = []
        for c in contributions:
            shap_value = c["shap_value"]
            flattened.append({
                "feature": c["feature"],
                "label": _humanize_feature_name(c["feature"]),
                "value": c["feature_value"],
                "shap_value": shap_value,
                "direction": "phishing" if shap_value > 0 else "safe",
            })
        return flattened

    # ── public interface ─────────────────────────────────────────────────

    def predict(self, features: dict) -> dict:
        row_df = self._encode(features)

        proba_phishing = float(self.model.predict_proba(row_df)[0][1])
        score, verdict, confidence = self._score_and_verdict(proba_phishing)

        visual_similarity_score = features.get("visual_similarity_score")
        has_login_form = features.get("dom_credential_form_detected")
        score = self._apply_visual_adjustment(score, visual_similarity_score, has_login_form)
        # Re-derive verdict in case the visual bump pushed the score across
        # a threshold boundary.
        if score >= 70:
            verdict = "PHISHING"
        elif score >= 35:
            verdict = "SUSPICIOUS"

        shap_list = []
        if self.rf_explainer is not None and self.xgb_explainer is not None:
            explanation = explain_single_row(
                row_df, self.rf_explainer, self.xgb_explainer, self.feature_order
            )
            shap_list = self._flatten_shap_for_schema(explanation)

        return {
            "score": score,
            "verdict": verdict,
            "confidence": confidence,
            "category": None,  # decision #6: no known source, TODO
            "is_zero_day": bool(features.get("whois_recently_registered", False)),
            "domain_age_days": features.get("whois_domain_age_days"),
            "registrar": features.get("whois_registrar"),
            "ssl_issuer": features.get("ssl_issuer"),
            "visual_similarity": visual_similarity_score,
            "closest_brand": features.get("closest_brand"),  # decision #5: now threaded through from pipeline.py
            "features": features,
            "shap": shap_list,
        }


# Loaded once, at import time - scan.py must import this singleton, not
# the Predictor class, or it defeats the entire point (see Phase 3.6
# summary section 2 - this was a real bug found and fixed in scan.py).
predictor = Predictor()