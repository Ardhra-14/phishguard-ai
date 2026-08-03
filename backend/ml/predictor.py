"""
Predictor - TEMPORARY placeholder for Phase 3 (ML model).

This is NOT the final ML model. Phase 3 is meant to train an XGBoost +
Random Forest ensemble on labeled phishing data (see requirements.txt:
xgboost, scikit-learn, shap are already present for that). This class
exists only so the real FeaturePipeline (Phase 1/2/4) can be exercised
end-to-end through the /scan endpoint before Phase 3 is built.

Replace this file's contents once the real trained model is ready - the
predict(features) interface below should stay the same so scan.py doesn't
need to change.
"""


class Predictor:
    """Rule-based stand-in for the real ML model."""

    def predict(self, features: dict) -> dict:
        lexical_risk = features.get("aggregate_lexical_risk_score", 0) or 0
        visual_score = features.get("visual_similarity_score")
        has_login_form = features.get("dom_credential_form_detected")

        # Simple weighted combination - NOT a trained model, just enough
        # to demonstrate the full pipeline flowing through to a verdict.
        score = lexical_risk * 60
        if visual_score is not None:
            score += visual_score * 25
        if has_login_form:
            score += 15

        score = min(round(score), 100)

        if score >= 60:
            verdict = "PHISHING"
        elif score >= 30:
            verdict = "SUSPICIOUS"
        else:
            verdict = "SAFE"

        return {
            "score": score,
            "verdict": verdict,
            "confidence": round(score / 100, 2),
            "category": None,
            "is_zero_day": features.get("whois_recently_registered", False),
            "domain_age_days": features.get("whois_domain_age_days"),
            "registrar": None,
            "ssl_issuer": None,
            "visual_similarity": visual_score,
            "closest_brand": None,
            "features": features,
            "shap": [],
        }
