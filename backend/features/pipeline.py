"""
Feature pipeline — Phase 1.

Merges URL lexical features, brand-impersonation scoring, TLD risk, and
IDN homograph detection into a single flat 30-key feature dict consumed
by the model in Phase 3. Slots for Phase 2 (DNS/WHOIS/SSL) and Phase 4
(visual clone detection) are present here as None and get filled in by
those phases.
"""
from urllib.parse import urlparse

from features.url_features import extract_url_features
from features.brand_detector import detect_brand_impersonation
from features.tld_scorer import score_tld
from features.idn_detector import detect_idn_homograph


class FeaturePipeline:
    """Orchestrates all Phase 1 (and later Phase 2/4) feature extractors."""

    async def extract(self, url: str) -> dict:
        """
        Extract the full feature dict for a URL.

        Returns a flat dict of 30 keys. In Phase 1 only the lexical,
        brand, TLD, and IDN groups are populated; DNS/WHOIS/SSL (Phase 2)
        and visual (Phase 4) keys are present but set to None until those
        phases are implemented.
        """
        domain = urlparse(url if "://" in url else f"https://{url}").netloc or url

        url_feats = extract_url_features(url)
        brand = detect_brand_impersonation(domain)
        tld = score_tld(domain)
        idn = detect_idn_homograph(domain)

        features = {
            # ── URL lexical features (12) ────────────────────────────
            **url_feats,

            # ── Brand impersonation (5) ──────────────────────────────
            "brand_impersonation_score": brand["score"],
            "brand_matched_count": len(brand["matched_brands"]),
            "brand_keyword_hit_count": len(brand["keyword_hits"]),
            "brand_typosquat_hit_count": len(brand["typosquat_hits"]),
            "brand_has_action_word": int(brand["has_action_word"]),

            # ── TLD risk (3) ──────────────────────────────────────────
            "tld": tld["tld"],
            "tld_risk_score": tld["risk"],
            "tld_known": int(tld["known"]),

            # ── IDN homograph (4) ────────────────────────────────────
            "idn_is_homograph": int(idn["is_homograph"]),
            "idn_confusable_count": len(idn["confusable_chars"]),
            "idn_risk_score": idn["risk_score"],
            "idn_punycode_flag": int(idn["punycode_flag"]),

            # ── Phase 2 stubs — DNS / WHOIS / SSL ────────────────────
            "dns_resolves": None,
            "whois_domain_age_days": None,
            "ssl_valid": None,

            # ── Phase 4 stubs — visual clone detection ───────────────
            "visual_similarity_score": None,
            "dom_credential_form_detected": None,
        }

        # Cheap aggregate lexical risk score (0-1) — a stand-in for the
        # real model output until Phase 3 trains XGBoost + Random Forest.
        features["aggregate_lexical_risk_score"] = round(
            min(
                0.4 * brand["score"]
                + 0.3 * tld["risk"]
                + 0.2 * idn["risk_score"]
                + 0.1 * min(url_feats["entropy"] / 5, 1.0),
                1.0,
            ),
            4,
        )

        return features
