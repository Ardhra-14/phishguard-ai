"""
Feature pipeline - Phase 1 + Phase 2 + Phase 4.

Merges URL lexical features, brand-impersonation scoring, TLD risk, IDN
homograph detection (Phase 1), DNS/WHOIS/SSL network features (Phase 2),
and visual clone detection (Phase 4) into a single flat feature dict
consumed by the model in Phase 3.
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
from features.visual.screenshot_capture import capture_screenshot
from features.visual.visual_scoring import analyze_screenshot


class FeaturePipeline:
    """Orchestrates all Phase 1/2/4 feature extractors."""

    async def extract(self, url: str) -> dict:
        domain = urlparse(url if "://" in url else f"https://{url}").netloc or url

        url_feats = extract_url_features(url)
        brand = detect_brand_impersonation(domain)
        tld = score_tld(domain)
        idn = detect_idn_homograph(domain)

        dns_result, whois_result, ssl_result, screenshot_result = await asyncio.gather(
            resolve_dns(domain),
            lookup_whois(domain),
            inspect_ssl(domain),
            capture_screenshot(url),
        )

        visual_similarity_score = None
        dom_credential_form_detected = None
        if screenshot_result["success"]:
            visual_analysis = analyze_screenshot(
                screenshot_result["screenshot_bytes"],
                claimed_domain=domain,
                html_content=screenshot_result.get("html_content"),
            )
            visual_similarity_score = visual_analysis["visual_similarity_score"]
            dom_credential_form_detected = visual_analysis["dom_credential_form_detected"]

        features = {
            **url_feats,

            "brand_impersonation_score": brand["score"],
            "brand_matched_count": len(brand["matched_brands"]),
            "brand_keyword_hit_count": len(brand["keyword_hits"]),
            "brand_typosquat_hit_count": len(brand["typosquat_hits"]),
            "brand_has_action_word": int(brand["has_action_word"]),

            "tld": tld["tld"],
            "tld_risk_score": tld["risk"],
            "tld_known": int(tld["known"]),

            "idn_is_homograph": int(idn["is_homograph"]),
            "idn_confusable_count": len(idn["confusable_chars"]),
            "idn_risk_score": idn["risk_score"],
            "idn_punycode_flag": int(idn["punycode_flag"]),

            "dns_resolves": dns_result["dns_resolves"],
            "dns_a_record_count": dns_result["dns_a_record_count"],
            "dns_has_aaaa": int(dns_result["dns_has_aaaa"]),
            "dns_has_mx": int(dns_result["dns_has_mx"]),

            "whois_domain_age_days": whois_result["whois_domain_age_days"],
            "whois_registrar": whois_result["whois_registrar"],
            "whois_recently_registered": int(whois_result["whois_recently_registered"]),
            "whois_privacy_protected": int(whois_result["whois_privacy_protected"]),
            "whois_found": int(whois_result["whois_found"]),

            "ssl_valid": ssl_result["ssl_valid"],
            "ssl_self_signed": int(ssl_result["ssl_self_signed"]),
            "ssl_issuer": ssl_result["ssl_issuer"],
            "ssl_days_until_expiry": ssl_result["ssl_days_until_expiry"],
            # ssl_expired is bool | None (None only when there's no cert to
            # check at all, e.g. nothing listening on 443) — left un-cast
            # like ssl_days_until_expiry so Phase 3 preprocessing can treat
            # "no cert present" as its own signal rather than coercing it
            # into False.
            "ssl_expired": ssl_result["ssl_expired"],

            "visual_similarity_score": visual_similarity_score,
            "dom_credential_form_detected": dom_credential_form_detected,
        }

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