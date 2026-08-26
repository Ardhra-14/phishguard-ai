"""
Phase 3 tests — ml/predictor.py's real ensemble wiring (Phase 3.6) and the
/api/v1/scan integration it feeds (Phase 3.7).

Uses the real trained model/meta/preprocessing artifacts (small, committed
static files — no mocking of joblib.load needed) but mocks predict_proba
for the score/verdict boundary tests so those assertions don't depend on
the model's actual learned weights. Network-touching pipeline stages
(DNS/WHOIS/SSL/screenshot) are mocked for the end-to-end test, following
the same offline-determinism convention as test_phase2.py.

Run with:  pytest tests/test_phase3.py -v
"""
from unittest.mock import AsyncMock, patch

import numpy as np
import pytest
from httpx import AsyncClient, ASGITransport

from ml.predictor import predictor, _normalize_ssl_issuer, _humanize_feature_name


# ── fixtures ──────────────────────────────────────────────────────────────

def _base_features() -> dict:
    """A complete, well-formed feature dict shaped like FeaturePipeline.extract()'s
    output, with every key the encoder reads populated. Individual tests
    override only the keys they care about."""
    return {
        "url_length": 20, "hyphen_count": 0, "dot_count": 1, "digit_count": 0,
        "entropy": 2.5, "subdomain_depth": 1, "has_https": 1, "is_ip_address": 0,
        "has_at_symbol": 0, "path_length": 0, "query_param_count": 0, "special_char_count": 0,
        "brand_impersonation_score": 0.0, "brand_matched_count": 0, "brand_keyword_hit_count": 0,
        "brand_typosquat_hit_count": 0, "brand_has_action_word": 0,
        "tld": "com", "tld_risk_score": 0.01, "tld_known": 1,
        "idn_is_homograph": 0, "idn_confusable_count": 0, "idn_risk_score": 0.0, "idn_punycode_flag": 0,
        "dns_resolves": True, "dns_a_record_count": 4, "dns_has_aaaa": 1, "dns_has_mx": 1,
        "whois_domain_age_days": 10569, "whois_registrar": "MarkMonitor, Inc.",
        "whois_recently_registered": 0, "whois_privacy_protected": 0, "whois_found": 1,
        "ssl_valid": True, "ssl_self_signed": 0, "ssl_issuer": "Google Trust Services",
        "ssl_days_until_expiry": 60, "ssl_expired": False,
        "aggregate_lexical_risk_score": 0.01,
        "visual_similarity_score": None, "dom_credential_form_detected": None,
    }


# ── ssl_issuer normalization ─────────────────────────────────────────────

def test_normalize_ssl_issuer_basic():
    assert _normalize_ssl_issuer("Google Trust Services") == "google_trust_services"
    assert _normalize_ssl_issuer("Amazon") == "amazon"
    assert _normalize_ssl_issuer("Sectigo Limited") == "sectigo_limited"


def test_normalize_ssl_issuer_preserves_apostrophe():
    """Matches the trained column name "ssl_issuer_let's_encrypt" exactly —
    apostrophes are kept, not stripped or turned into underscores."""
    assert _normalize_ssl_issuer("Let's Encrypt") == "let's_encrypt"


def test_normalize_ssl_issuer_hyphen_becomes_underscore():
    assert _normalize_ssl_issuer("GlobalSign nv-sa") == "globalsign_nv_sa"


def test_normalize_ssl_issuer_digicert_collision():
    """The documented (not a bug) collision from the Phase 3.6 summary:
    "DigiCert Inc" and "DigiCert, Inc." both land on the same normalized
    value / one-hot column, which is why preprocessing_artifacts.json has
    10 ssl_issuer_top_values but meta.json only has 9 named columns."""
    assert _normalize_ssl_issuer("DigiCert Inc") == "digicert_inc"
    assert _normalize_ssl_issuer("DigiCert, Inc.") == "digicert_inc"


# ── predictor._encode() ──────────────────────────────────────────────────

def test_encode_produces_all_54_columns_in_order():
    row_df = predictor._encode(_base_features())
    assert list(row_df.columns) == predictor.feature_order
    assert len(row_df.columns) == 54
    assert len(row_df) == 1


def test_encode_passthrough_values():
    features = _base_features()
    features["url_length"] = 77
    features["entropy"] = 3.14
    row_df = predictor._encode(features)
    assert row_df["url_length"].iloc[0] == 77
    assert row_df["entropy"].iloc[0] == 3.14


def test_encode_bool_passthrough_cast_to_int():
    features = _base_features()
    features["dns_resolves"] = True
    features["ssl_valid"] = False
    row_df = predictor._encode(features)
    assert row_df["dns_resolves"].iloc[0] == 1
    assert row_df["ssl_valid"].iloc[0] == 0


def test_encode_sentinel_fill_for_missing_numeric():
    """Missing (None) numeric feature -> preprocessing_artifacts.json's
    sentinel_value (-1), not 0 and not NaN."""
    features = _base_features()
    features["whois_domain_age_days"] = None
    features["ssl_days_until_expiry"] = None
    row_df = predictor._encode(features)
    assert row_df["whois_domain_age_days"].iloc[0] == predictor.sentinel == -1
    assert row_df["ssl_days_until_expiry"].iloc[0] == -1


def test_encode_sentinel_fill_for_missing_boolean():
    """A missing boolean (e.g. ssl_expired is None because there was no
    cert to check) also falls back to the sentinel, not False/0 — "no
    data" must stay distinguishable from "checked, found false"."""
    features = _base_features()
    features["ssl_expired"] = None
    row_df = predictor._encode(features)
    assert row_df["ssl_expired"].iloc[0] == -1


def test_encode_missing_flags_set_correctly():
    features = _base_features()
    features["whois_registrar"] = None
    features["ssl_issuer"] = None
    row_df = predictor._encode(features)
    assert row_df["whois_registrar_was_missing"].iloc[0] == 1
    assert row_df["ssl_issuer_was_missing"].iloc[0] == 1
    # unaffected flags stay 0
    assert row_df["whois_domain_age_days_was_missing"].iloc[0] == 0
    assert row_df["ssl_days_until_expiry_was_missing"].iloc[0] == 0
    assert row_df["ssl_expired_was_missing"].iloc[0] == 0


def test_encode_unseen_tld_frequency_zero():
    """Unseen category -> frequency 0.0 (decision #1), not sentinel, not KeyError."""
    features = _base_features()
    features["tld"] = "this-tld-does-not-exist-anywhere"
    row_df = predictor._encode(features)
    assert row_df["tld_freq"].iloc[0] == 0.0


def test_encode_known_tld_frequency_matches_artifact():
    features = _base_features()
    features["tld"] = "com"
    row_df = predictor._encode(features)
    assert row_df["tld_freq"].iloc[0] == predictor.tld_freq_map["com"]
    assert row_df["tld_freq"].iloc[0] > 0


def test_encode_unseen_registrar_frequency_zero():
    features = _base_features()
    features["whois_registrar"] = "Some Totally Unknown Registrar LLC"
    row_df = predictor._encode(features)
    assert row_df["whois_registrar_freq"].iloc[0] == 0.0


def test_encode_missing_registrar_uses_missing_bucket_not_zero():
    """Per the Phase 3.7 handoff: missing whois_registrar must look up the
    "__missing__" bucket in the frequency map (a real, non-zero value),
    not just default straight to 0.0 like a genuinely unseen registrar."""
    features = _base_features()
    features["whois_registrar"] = None
    row_df = predictor._encode(features)
    expected = predictor.registrar_freq_map["__missing__"]
    assert expected > 0  # sanity: the bucket itself is meaningful
    assert row_df["whois_registrar_freq"].iloc[0] == expected
    assert row_df["whois_registrar_freq"].iloc[0] != 0.0


def test_encode_ssl_issuer_one_hot_known_value():
    features = _base_features()
    features["ssl_issuer"] = "Let's Encrypt"
    row_df = predictor._encode(features)
    assert row_df["ssl_issuer_let's_encrypt"].iloc[0] == 1
    assert row_df["ssl_issuer_missing"].iloc[0] == 0
    assert row_df["ssl_issuer_other"].iloc[0] == 0
    # every other ssl_issuer_* one-hot column stays 0
    other_cols = [c for c in predictor._ssl_issuer_columns if c != "ssl_issuer_let's_encrypt"]
    assert all(row_df[c].iloc[0] == 0 for c in other_cols)


def test_encode_ssl_issuer_one_hot_digicert_collision():
    features_a = _base_features()
    features_a["ssl_issuer"] = "DigiCert Inc"
    features_b = _base_features()
    features_b["ssl_issuer"] = "DigiCert, Inc."

    row_a = predictor._encode(features_a)
    row_b = predictor._encode(features_b)

    assert row_a["ssl_issuer_digicert_inc"].iloc[0] == 1
    assert row_b["ssl_issuer_digicert_inc"].iloc[0] == 1


def test_encode_ssl_issuer_missing():
    features = _base_features()
    features["ssl_issuer"] = None
    row_df = predictor._encode(features)
    assert row_df["ssl_issuer_missing"].iloc[0] == 1
    assert row_df["ssl_issuer_other"].iloc[0] == 0


def test_encode_ssl_issuer_unseen_goes_to_other():
    features = _base_features()
    features["ssl_issuer"] = "Some Random CA Nobody Has Heard Of"
    row_df = predictor._encode(features)
    assert row_df["ssl_issuer_other"].iloc[0] == 1
    assert row_df["ssl_issuer_missing"].iloc[0] == 0


# ── predictor's score/verdict mapping ────────────────────────────────────

@pytest.mark.parametrize("proba,expected_score,expected_verdict", [
    (0.00, 0, "SAFE"),
    (0.34, 34, "SAFE"),
    (0.35, 35, "SUSPICIOUS"),
    (0.69, 69, "SUSPICIOUS"),
    (0.70, 70, "PHISHING"),
    (1.00, 100, "PHISHING"),
])
def test_score_and_verdict_thresholds(proba, expected_score, expected_verdict):
    score, verdict, confidence = predictor._score_and_verdict(proba)
    assert score == expected_score
    assert verdict == expected_verdict
    assert confidence == round(proba, 2)


def test_predict_end_to_end_uses_mocked_probability():
    """Mocks the underlying model's predict_proba so the score/verdict
    assertion doesn't depend on the model's actual learned weights."""
    features = _base_features()
    fake_proba = np.array([[0.1, 0.9]])  # P(phishing) = 0.9 -> score 90
    with patch.object(predictor.model, "predict_proba", return_value=fake_proba):
        result = predictor.predict(features)
    assert result["score"] == 90
    assert result["verdict"] == "PHISHING"
    assert result["confidence"] == 0.9


def test_predict_returns_registrar_and_ssl_issuer_from_features():
    features = _base_features()
    features["whois_registrar"] = "NameCheap, Inc."
    features["ssl_issuer"] = "Sectigo Limited"
    fake_proba = np.array([[0.9, 0.1]])
    with patch.object(predictor.model, "predict_proba", return_value=fake_proba):
        result = predictor.predict(features)
    assert result["registrar"] == "NameCheap, Inc."
    assert result["ssl_issuer"] == "Sectigo Limited"
    assert result["domain_age_days"] == features["whois_domain_age_days"]


def test_predict_category_and_closest_brand_stay_none():
    """Decisions #5/#6: neither key exists anywhere in FeaturePipeline's
    output yet, so these must stay None rather than raising or guessing."""
    features = _base_features()
    fake_proba = np.array([[0.9, 0.1]])
    with patch.object(predictor.model, "predict_proba", return_value=fake_proba):
        result = predictor.predict(features)
    assert result["category"] is None
    assert result["closest_brand"] is None


def test_predict_surfaces_closest_brand_when_present():
    """Phase 3.7 fix: pipeline.py now threads closest_brand through from
    analyze_screenshot()'s brand-similarity check, so predictor.py's
    features.get("closest_brand") should stop always returning None once
    the pipeline actually finds a visual brand match."""
    features = _base_features()
    features["closest_brand"] = "paypal"
    fake_proba = np.array([[0.1, 0.9]])
    with patch.object(predictor.model, "predict_proba", return_value=fake_proba):
        result = predictor.predict(features)
    assert result["closest_brand"] == "paypal"


# ── visual-score blend (_apply_visual_adjustment) ────────────────────────

def test_visual_adjustment_no_bump_below_threshold():
    assert predictor._apply_visual_adjustment(50, 0.79, True) == 50
    assert predictor._apply_visual_adjustment(50, None, True) == 50


def test_visual_adjustment_bump_with_login_form():
    assert predictor._apply_visual_adjustment(50, 0.80, True) == 62
    assert predictor._apply_visual_adjustment(50, 0.95, True) == 62


def test_visual_adjustment_bump_without_login_form():
    assert predictor._apply_visual_adjustment(50, 0.80, False) == 56
    assert predictor._apply_visual_adjustment(50, 0.80, None) == 56


def test_visual_adjustment_never_exceeds_100():
    assert predictor._apply_visual_adjustment(95, 0.99, True) == 100
    assert predictor._apply_visual_adjustment(100, 0.99, True) == 100
    assert predictor._apply_visual_adjustment(90, 0.80, False) == 96


def test_predict_visual_bump_can_flip_verdict_across_boundary():
    """A score just under the SUSPICIOUS threshold should cross it once
    the visual bump is applied — verdict must be re-derived after the bump,
    not computed only from the raw model probability."""
    features = _base_features()
    features["visual_similarity_score"] = 0.85
    features["dom_credential_form_detected"] = True
    fake_proba = np.array([[0.4, 0.6]])  # raw score 60 -> SUSPICIOUS alone
    with patch.object(predictor.model, "predict_proba", return_value=fake_proba):
        result = predictor.predict(features)
    assert result["score"] == 72  # 60 + 12
    assert result["verdict"] == "PHISHING"  # crossed the 70 threshold


# ── SHAP flattening ───────────────────────────────────────────────────────

def test_humanize_feature_name():
    assert _humanize_feature_name("whois_domain_age_days") == "Whois Domain Age Days"
    assert _humanize_feature_name("url_length") == "Url Length"


def test_flatten_shap_for_schema_shape_and_direction():
    explanation = {
        "random_forest": {
            "base_value": 0.5,
            "top_contributions": [
                {"feature": "url_length", "shap_value": 0.12, "feature_value": 45.0},
                {"feature": "whois_domain_age_days", "shap_value": -0.08, "feature_value": 10569.0},
                {"feature": "entropy", "shap_value": 0.0, "feature_value": 2.5},
            ],
        },
        "xgboost": {"base_value": 0.0, "top_contributions": []},
    }
    flattened = predictor._flatten_shap_for_schema(explanation)

    assert len(flattened) == 3
    for item in flattened:
        assert set(item.keys()) == {"feature", "label", "value", "shap_value", "direction"}

    assert flattened[0]["feature"] == "url_length"
    assert flattened[0]["label"] == "Url Length"
    assert flattened[0]["value"] == 45.0
    assert flattened[0]["direction"] == "phishing"  # positive shap_value

    assert flattened[1]["direction"] == "safe"  # negative shap_value
    assert flattened[2]["direction"] == "safe"  # zero shap_value treated as non-phishing-pushing


def test_flatten_shap_only_surfaces_random_forest_component():
    """Decision #7: XGBoost's log-odds contributions must not leak into
    the flat list, since they're not on the same scale as RF's."""
    explanation = {
        "random_forest": {"base_value": 0.5, "top_contributions": [
            {"feature": "url_length", "shap_value": 0.1, "feature_value": 20.0},
        ]},
        "xgboost": {"base_value": 0.0, "top_contributions": [
            {"feature": "entropy", "shap_value": 5.0, "feature_value": 3.0},
        ]},
    }
    flattened = predictor._flatten_shap_for_schema(explanation)
    features_in_output = [item["feature"] for item in flattened]
    assert "url_length" in features_in_output
    assert "entropy" not in features_in_output


# ── end-to-end /api/v1/scan smoke test ───────────────────────────────────

@pytest.fixture
def _mocked_pipeline_stages():
    """Mocks every network-touching FeaturePipeline stage so the full
    /api/v1/scan route can run offline and deterministically — same
    convention as test_phase2.py's pipeline integration tests."""
    def _apply(dns_resolves, whois_age_days, ssl_valid, ssl_issuer):
        return (
            patch("features.pipeline.resolve_dns", new=AsyncMock(return_value={
                "dns_resolves": dns_resolves, "dns_a_record_count": 4 if dns_resolves else 0,
                "dns_has_aaaa": dns_resolves, "dns_has_mx": dns_resolves,
                "dns_resolved_ips": ["1.2.3.4"] if dns_resolves else [],
            })),
            patch("features.pipeline.lookup_whois", new=AsyncMock(return_value={
                "whois_found": True, "whois_domain_age_days": whois_age_days,
                "whois_recently_registered": whois_age_days < 30,
                "whois_privacy_protected": False, "whois_registrar": "MarkMonitor, Inc.",
            })),
            patch("features.pipeline.inspect_ssl", new=AsyncMock(return_value={
                "ssl_valid": ssl_valid, "ssl_self_signed": False,
                "ssl_issuer": ssl_issuer, "ssl_days_until_expiry": 90 if ssl_valid else None,
                "ssl_expired": False if ssl_valid else None,
            })),
            patch("features.pipeline.capture_screenshot", new=AsyncMock(return_value={
                "success": False,  # keep visual stage a no-op for this smoke test
            })),
        )
    return _apply


async def test_scan_endpoint_legit_domain_returns_low_score(_mocked_pipeline_stages):
    patches = _mocked_pipeline_stages(
        dns_resolves=True, whois_age_days=10569, ssl_valid=True, ssl_issuer="Google Trust Services",
    )
    with patches[0], patches[1], patches[2], patches[3]:
        async with AsyncClient(transport=ASGITransport(app=_get_app()), base_url="http://test") as client:
            response = await client.post("/api/v1/scan", json={"url": "https://www.google.com"})

    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] in ("SAFE", "SUSPICIOUS")  # loose bucket check, not exact score
    assert 0 <= data["score"] <= 100
    assert isinstance(data["shap"], list)
    assert data["registrar"] == "MarkMonitor, Inc."


async def test_scan_endpoint_phishing_style_domain_returns_high_score(_mocked_pipeline_stages):
    patches = _mocked_pipeline_stages(
        dns_resolves=False, whois_age_days=1, ssl_valid=False, ssl_issuer=None,
    )
    with patches[0], patches[1], patches[2], patches[3]:
        async with AsyncClient(transport=ASGITransport(app=_get_app()), base_url="http://test") as client:
            response = await client.post(
                "/api/v1/scan", json={"url": "http://paypal-verify-account-secure.tk"}
            )

    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] in ("SUSPICIOUS", "PHISHING")  # loose bucket check
    assert data["is_zero_day"] is True


async def test_scan_endpoint_surfaces_closest_brand_from_visual_stage():
    """Phase 3.7 fix, end-to-end: a page that visually matches a known
    brand should have that brand name come back in the /api/v1/scan
    response's closest_brand field, not just buried in the
    /scan/image-only response like before."""
    with patch("features.pipeline.resolve_dns", new=AsyncMock(return_value={
                "dns_resolves": False, "dns_a_record_count": 0,
                "dns_has_aaaa": False, "dns_has_mx": False, "dns_resolved_ips": [],
            })), \
         patch("features.pipeline.lookup_whois", new=AsyncMock(return_value={
                "whois_found": False, "whois_domain_age_days": None,
                "whois_recently_registered": False,
                "whois_privacy_protected": False, "whois_registrar": None,
            })), \
         patch("features.pipeline.inspect_ssl", new=AsyncMock(return_value={
                "ssl_valid": False, "ssl_self_signed": False,
                "ssl_issuer": None, "ssl_days_until_expiry": None, "ssl_expired": None,
            })), \
         patch("features.pipeline.capture_screenshot", new=AsyncMock(return_value={
                "success": True, "screenshot_bytes": b"fake", "html_content": "<html></html>",
            })), \
         patch("features.pipeline.analyze_screenshot", return_value={
                "visual_similarity_score": 0.92,
                "dom_credential_form_detected": True,
                "details": {"brand_similarity": {"closest_brand": "paypal"}},
            }):
        async with AsyncClient(transport=ASGITransport(app=_get_app()), base_url="http://test") as client:
            response = await client.post(
                "/api/v1/scan", json={"url": "http://paypal-secure-login.tk"}
            )

    assert response.status_code == 200
    data = response.json()
    assert data["closest_brand"] == "paypal"


def _get_app():
    from main import app
    return app