"""
Phase 1 tests — URL lexical features, brand impersonation, TLD risk,
IDN homograph detection, and the merged feature pipeline.

Covers the 3 fixes from the previous chat:
  Fix 1 — brand_detector.py: keyword-hit weight raised 0.2 -> 0.25
  Fix 2 — brand_detector.py: Levenshtein now compares each hyphen-split
          domain token separately instead of the whole hyphenated string
  Fix 3 — this file: single top-level import, no duplicate import inside
          the async pipeline test

Run with:  pytest tests/test_phase1.py -v
"""
from features.url_features import extract_url_features
from features.brand_detector import detect_brand_impersonation
from features.tld_scorer import score_tld
from features.idn_detector import detect_idn_homograph
from features.pipeline import FeaturePipeline


# ── url_features.py ──────────────────────────────────────────────────────

def test_url_length_feature():
    url = "https://secure-sbi-login.xyz/verify/account"
    assert extract_url_features(url)["url_length"] == len(url)


def test_hyphen_count_feature():
    feats = extract_url_features("https://secure-sbi-login.xyz")
    assert feats["hyphen_count"] == 2


def test_https_detection():
    assert extract_url_features("https://example.com")["has_https"] == 1
    assert extract_url_features("http://example.com")["has_https"] == 0


def test_ip_address_detection():
    assert extract_url_features("http://192.168.1.1/login")["is_ip_address"] == 1
    assert extract_url_features("http://example.com")["is_ip_address"] == 0


def test_entropy_higher_for_random_domain():
    random_feats = extract_url_features("https://xk29fj83qz.com")
    normal_feats = extract_url_features("https://google.com")
    assert random_feats["entropy"] > normal_feats["entropy"]


def test_subdomain_depth():
    assert extract_url_features("https://a.b.example.com")["subdomain_depth"] == 2
    assert extract_url_features("https://example.com")["subdomain_depth"] == 0


# ── brand_detector.py ────────────────────────────────────────────────────

def test_high_impersonation_score():
    """Fix 1: two keyword hits at weight 0.25 + action-word boost crosses
    0.6. Under the old 0.2 weight this would only reach 0.55."""
    result = detect_brand_impersonation("sbi-hdfc-alert.info")
    assert result["score"] >= 0.6
    assert "SBI" in result["matched_brands"]
    assert "HDFC" in result["matched_brands"]


def test_levenshtein_close_to_sbi():
    """Fix 2: comparing the token 'sb1' on its own (not 'sb1-login' as one
    string) catches the 1-character typosquat of 'sbi'."""
    result = detect_brand_impersonation("sb1-login.com")
    assert "SBI" in result["matched_brands"]
    assert any(hit["token"] == "sb1" and hit["distance"] == 1 for hit in result["typosquat_hits"])


def test_no_false_positive_on_legit_unrelated_domain():
    result = detect_brand_impersonation("wikipedia.org")
    assert result["score"] == 0.0
    assert result["matched_brands"] == []


def test_multiple_brand_keyword_hits_increase_score():
    one_hit = detect_brand_impersonation("sbi-service.com")
    two_hits = detect_brand_impersonation("sbi-hdfc-service.com")
    assert two_hits["score"] > one_hit["score"]


def test_action_word_boost():
    no_action = detect_brand_impersonation("sbi-info.com")
    with_action = detect_brand_impersonation("sbi-verify.com")
    assert with_action["has_action_word"] is True
    assert no_action["has_action_word"] is False
    assert with_action["score"] > no_action["score"]


def test_matched_brands_list_populated():
    result = detect_brand_impersonation("upi-payment-alert.xyz")
    assert "UPI" in result["matched_brands"]
    assert "upi" in result["keyword_hits"]


def test_score_capped_at_one():
    result = detect_brand_impersonation(
        "sbi-hdfc-icici-paytm-upi-aadhaar-verify-login-secure-account.xyz"
    )
    assert result["score"] == 1.0


# ── tld_scorer.py ────────────────────────────────────────────────────────

def test_xyz_tld_high_risk():
    assert score_tld("secure-login.xyz")["risk"] == 0.94


def test_tk_tld_high_risk():
    assert score_tld("free-gift.tk")["risk"] == 0.96


def test_gov_in_low_risk():
    result = score_tld("incometax.gov.in")
    assert result["tld"] == "gov.in"
    assert result["risk"] == 0.01


def test_unknown_tld_default_risk():
    result = score_tld("something.qzxy")
    assert result["known"] is False
    assert result["risk"] == 0.5


def test_com_moderate_risk():
    assert score_tld("example.com")["risk"] == 0.15


# ── idn_detector.py ──────────────────────────────────────────────────────

def test_cyrillic_a_homograph_detected():
    result = detect_idn_homograph("sb\u0430.com")  # Cyrillic 'а' (U+0430)
    assert result["is_homograph"] is True
    assert len(result["confusable_chars"]) == 1
    assert result["confusable_chars"][0]["looks_like"] == "a"


def test_clean_ascii_domain_not_homograph():
    result = detect_idn_homograph("sbi.com")
    assert result["is_homograph"] is False
    assert result["confusable_chars"] == []
    assert result["risk_score"] == 0.0


def test_punycode_flag_detected():
    result = detect_idn_homograph("xn--sb-lka.com")
    assert result["punycode_flag"] is True
    assert result["is_homograph"] is True


def test_confusable_char_metadata():
    result = detect_idn_homograph("sb\u0430.com")
    char_info = result["confusable_chars"][0]
    assert char_info["codepoint"] == "U+0430"
    assert char_info["char"] == "\u0430"


# ── pipeline.py ──────────────────────────────────────────────────────────
#
# NOTE: as of Phase 2, resolve_dns/lookup_whois/inspect_ssl are real network
# calls, so pipeline-level tests here patch them to keep this file offline
# and deterministic (Phase 2's own network-layer tests live in
# tests/test_phase2.py). The stale "returns 30 keys" / "Phase 2 stubs are
# None" assumptions from the original Phase 1 rebuild no longer hold now
# that Phase 2 fills those keys in — updated accordingly below.

from unittest.mock import patch, AsyncMock

_FAKE_DNS = {"dns_resolves": True, "dns_a_record_count": 1, "dns_has_aaaa": False,
             "dns_has_mx": True, "dns_resolved_ips": ["93.184.216.34"]}
_FAKE_WHOIS = {"whois_found": True, "whois_domain_age_days": 4000,
               "whois_recently_registered": False, "whois_privacy_protected": False}
_FAKE_SSL = {"ssl_valid": True, "ssl_self_signed": False, "ssl_issuer": "DigiCert",
             "ssl_days_until_expiry": 100, "ssl_expired": False}


def _patched_pipeline():
    return patch.multiple(
        "features.pipeline",
        resolve_dns=AsyncMock(return_value=_FAKE_DNS),
        lookup_whois=AsyncMock(return_value=_FAKE_WHOIS),
        inspect_ssl=AsyncMock(return_value=_FAKE_SSL),
    )


async def test_pipeline_returns_38_keys():
    """12 URL + 5 brand + 3 TLD + 4 IDN + 4 DNS + 4 WHOIS + 3 SSL
    + 2 Phase-4 stubs + 1 aggregate score = 38 total keys, up from the
    original Phase 1 count of 30 now that Phase 2's DNS/WHOIS/SSL groups
    (11 keys) have replaced the old 3-key None stub."""
    with _patched_pipeline():
        pipeline = FeaturePipeline()
        features = await pipeline.extract("https://example.com")
    assert len(features) == 38


async def test_phishing_scores_higher_than_legit():
    """Fix 3: single import at the top of this file — no duplicate
    'from features.pipeline import FeaturePipeline' inside the test body,
    which previously caused a redefinition error in the async test."""
    with _patched_pipeline():
        pipeline = FeaturePipeline()
        phishing_features = await pipeline.extract("https://secure-sbi-login-verify.xyz")
        legit_features = await pipeline.extract("https://www.onlinesbi.com")

    assert phishing_features["aggregate_lexical_risk_score"] > legit_features["aggregate_lexical_risk_score"]


async def test_pipeline_phase2_populated_phase4_still_stubs():
    with _patched_pipeline():
        pipeline = FeaturePipeline()
        features = await pipeline.extract("https://example.com")
    assert features["dns_resolves"] is True
    assert features["whois_domain_age_days"] == 4000
    assert features["ssl_valid"] is True
    assert features["visual_similarity_score"] is None
    assert features["dom_credential_form_detected"] is None
