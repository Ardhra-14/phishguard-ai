"""
Visual scoring - Phase 4 (Visual Detection).

Combines DOM analysis (real HTML - preferred, when available), image
features (OCR/pixels - fallback for static uploads with no HTML), and
brand similarity (visual clone detection) into a final verdict.
"""
from features.visual.image_features import extract_image_features
from features.visual.brand_similarity import compare_to_brands
from features.visual.dom_analyzer import analyze_dom

WEIGHT_LOGIN_FORM = 30
WEIGHT_URGENCY = 20
WEIGHT_CREDENTIAL_KEYWORDS = 15
WEIGHT_BRAND_CLONE = 35
WEIGHT_CROSS_DOMAIN_FORM = 25  # form submits to a different domain - strong signal


def analyze_screenshot(
    screenshot_bytes: bytes,
    claimed_domain: str | None = None,
    html_content: str | None = None,
) -> dict:
    """
    Full visual + DOM analysis.

    Args:
        screenshot_bytes: raw PNG/JPEG bytes of the page screenshot.
        claimed_domain: the domain the page is hosted on, if known.
        html_content: rendered HTML of the page, if available (auto-capture
            path only - manual uploads have no HTML, just an image).
    """
    brand_result = compare_to_brands(screenshot_bytes)

    reasons = []
    score = 0
    login_form_detected = False
    cross_domain_form = False

    if html_content:
        # Preferred path: real DOM inspection, no OCR guessing.
        dom_result = analyze_dom(html_content)
        login_form_detected = dom_result["login_form_detected"]
        reasons.extend(dom_result["reasons"])

        if login_form_detected:
            score += WEIGHT_LOGIN_FORM
        if dom_result["urgency_text_hits"]:
            score += WEIGHT_URGENCY
        if dom_result["form_action_domains"] and claimed_domain:
            for action_url in dom_result["form_action_domains"]:
                if claimed_domain not in action_url:
                    cross_domain_form = True
                    score += WEIGHT_CROSS_DOMAIN_FORM
                    reasons.append(
                        f"Form submits to a different domain than the page itself: {action_url}"
                    )
                    break
        img_features = None
    else:
        # Fallback path: manual upload, no HTML available - use OCR/pixels.
        img_features = extract_image_features(screenshot_bytes)
        reasons.extend(img_features["reasons"])
        login_form_detected = img_features["login_form_detected"]

        if login_form_detected:
            score += WEIGHT_LOGIN_FORM
        if img_features["urgency_keyword_hits"]:
            score += WEIGHT_URGENCY
        if img_features["credential_keyword_hits"]:
            score += WEIGHT_CREDENTIAL_KEYWORDS

    brand_clone_flagged = False
    if brand_result["is_likely_clone"]:
        closest_brand = brand_result["closest_brand"]
        domain_matches_brand = (
            claimed_domain is not None and closest_brand in claimed_domain.lower()
        )
        if not domain_matches_brand:
            score += WEIGHT_BRAND_CLONE
            brand_clone_flagged = True
            reasons.append(
                f"Visually resembles {closest_brand.upper()} "
                f"(hash distance {brand_result['hash_distance']}) but domain doesn't match"
            )

    score = min(score, 100)

    if score >= 60:
        verdict = "Phishing"
    elif score >= 30:
        verdict = "Suspicious"
    else:
        verdict = "Legitimate"

    confidence = round(score / 100, 2)

    if not reasons:
        reasons.append("No significant phishing indicators detected")

    return {
        "visual_similarity_score": brand_result["visual_similarity_score"],
        "dom_credential_form_detected": login_form_detected,
        "verdict": verdict,
        "confidence": confidence,
        "score": score,
        "reasons": reasons,
        "analysis_method": "dom" if html_content else "image_ocr",
        "details": {
            "image_features": img_features,
            "brand_similarity": brand_result,
            "brand_clone_flagged": brand_clone_flagged,
            "cross_domain_form": cross_domain_form,
        },
    }
