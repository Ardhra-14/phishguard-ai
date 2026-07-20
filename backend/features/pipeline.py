"""
Feature pipeline — Phase 1 + Phase 2.

Merges URL lexical features, brand-impersonation scoring, TLD risk, IDN
homograph detection (Phase 1), and DNS/WHOIS/SSL network features (Phase 2)
into a single flat feature dict consumed by the model in Phase 3. Slots for
Phase 4 (visual clone detection) are present here as None and get filled in
once that phase is implemented.
"""
import asyncio
from urllib.parse import urlparse

from features.url_features import extract_url_features
from features.brand_detector import detect_brand_impersonation
from features.tld_scorer import score_tld
from features.idn_detector import detect_idn_homograph
from features.dns_resolver import resolve_dns
from features.whois_lookup import lookup_whois
from features.ssl_inspector import inspect_ssl


class FeaturePipeline:
    """Orchestrates all Phase 1/2 (and later Phase 4) feature extractors."""

    async def extract(self, url: str) -> dict:
        """
        Extract the full feature dict for a URL.

        Lexical, brand, TLD, and IDN groups (Phase 1) are pure/offline and
        run synchronously. DNS, WHOIS, and SSL lookups (Phase 2) are
        independent network calls, so they run concurrently via
        asyncio.gather rather than sequentially — otherwise a single scan
        could take DNS_TIMEOUT + WHOIS_TIMEOUT + SSL_TIMEOUT seconds
        end-to-end instead of max() of the three.

        Visual (Phase 4) keys are present but set to None until that phase
        is implemented.
        """
        domain = urlparse(url if "://" in url else f"https://{url}").netloc or url

        url_feats = extract_url_features(url)
        brand = detect_brand_impersonation(domain)
        tld = score_tld(domain)
        idn = detect_idn_homograph(domain)

        dns_result, whois_result, ssl_result = await asyncio.gather(
            resolve_dns(domain),
            lookup_whois(domain),
            inspect_ssl(domain),
        )

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

            # ── DNS (4) ───────────────────────────────────────────────
            "dns_resolves": dns_result["dns_resolves"],
            "dns_a_record_count": dns_result["dns_a_record_count"],
            "dns_has_aaaa": int(dns_result["dns_has_aaaa"]),
            "dns_has_mx": int(dns_result["dns_has_mx"]),

            # ── WHOIS (4) ─────────────────────────────────────────────
            "whois_domain_age_days": whois_result["whois_domain_age_days"],
            "whois_recently_registered": int(whois_result["whois_recently_registered"]),
            "whois_privacy_protected": int(whois_result["whois_privacy_protected"]),
            "whois_found": int(whois_result["whois_found"]),

            # ── SSL (3) ───────────────────────────────────────────────
            "ssl_valid": ssl_result["ssl_valid"],
            "ssl_self_signed": int(ssl_result["ssl_self_signed"]),
            "ssl_days_until_expiry": ssl_result["ssl_days_until_expiry"],

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
