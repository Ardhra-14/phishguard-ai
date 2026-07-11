"""
Brand impersonation detector — Phase 1.

Flags domains that inject Indian brand keywords (SBI, HDFC, UPI, NPCI, GOV,
...) or that are Levenshtein-close typosquats of those brands.
"""
import json
import re
from pathlib import Path

from rapidfuzz.distance import Levenshtein

_DATA_PATH = Path(__file__).resolve().parent.parent / "data" / "brand_dict.json"

with open(_DATA_PATH, "r", encoding="utf-8") as f:
    _BRAND_DICT: dict[str, list[str]] = json.load(f)

# Weight added to the impersonation score for every distinct brand keyword
# found injected into the domain.
# Fix 1: raised from 0.2 -> 0.25 so that two co-occurring brand keywords
# (e.g. "sbi" + "hdfc" injected into the same lure domain) cross the 0.5
# threshold on their own, before any action-word boost is applied.
KEYWORD_HIT_WEIGHT = 0.25

# Extra weight when a brand keyword is paired with a phishing "action" word
# (e.g. sbi + login, hdfc + verify) — a classic credential-harvest pattern.
ACTION_WORD_BOOST = 0.15

# Max Levenshtein distance for a domain token to be considered a typosquat
# of a brand keyword.
MAX_TYPOSQUAT_DISTANCE = 2

_ACTION_WORDS = {
    "login", "secure", "verify", "update", "account", "confirm", "support",
    "service", "alert", "suspend", "kyc", "otp", "reward", "offer", "bonus",
    "free", "claim", "bank", "signin", "password", "reset",
}


def _domain_tokens(domain: str) -> list[str]:
    """
    Split a domain into comparable tokens.

    Fix 2: the original implementation Levenshtein-compared the *entire*
    hyphenated domain string against each brand keyword in one shot, e.g.
    "sb1-login" vs "sbi" — the "-login" suffix inflated the edit distance
    past the threshold and hid the typosquat. Here each hyphen-separated
    (and dot-separated) label is compared on its own, so "sb1-login.com"
    yields tokens ["sb1", "login", "com"], and "sb1" alone scores an edit
    distance of 1 against "sbi" instead of a diluted 6+.
    """
    domain = domain.lower()
    domain = re.sub(r"^https?://", "", domain)
    domain = domain.split("/")[0].split(":")[0]
    if domain.startswith("www."):
        domain = domain[4:]

    tokens: list[str] = []
    for dot_part in domain.split("."):
        for hyphen_part in dot_part.split("-"):
            if hyphen_part:
                tokens.append(hyphen_part)
    return tokens


def detect_brand_impersonation(domain: str) -> dict:
    """
    Score a domain for Indian-brand impersonation.

    Returns:
        {
          "score": float 0-1,
          "matched_brands": [str, ...],
          "keyword_hits": [str, ...],
          "typosquat_hits": [{"token", "brand", "keyword", "distance"}, ...],
          "has_action_word": bool,
        }
    """
    tokens = _domain_tokens(domain)
    collapsed = "".join(tokens)  # for substring keyword checks

    matched_brands: set[str] = set()
    keyword_hits: list[str] = []
    typosquat_hits: list[dict] = []
    score = 0.0

    # 1) Direct keyword injection — brand keyword appears as a substring
    for brand, keywords in _BRAND_DICT.items():
        for kw in keywords:
            if kw in collapsed:
                matched_brands.add(brand)
                keyword_hits.append(kw)
                score += KEYWORD_HIT_WEIGHT

    # 2) Typosquat detection — compare each token separately (Fix 2)
    for token in tokens:
        if len(token) < 3:
            continue
        for brand, keywords in _BRAND_DICT.items():
            for kw in keywords:
                if abs(len(token) - len(kw)) > MAX_TYPOSQUAT_DISTANCE:
                    continue
                dist = Levenshtein.distance(token, kw)
                if 0 < dist <= MAX_TYPOSQUAT_DISTANCE:
                    matched_brands.add(brand)
                    typosquat_hits.append(
                        {"token": token, "brand": brand, "keyword": kw, "distance": dist}
                    )
                    score += KEYWORD_HIT_WEIGHT * (1 - dist / (MAX_TYPOSQUAT_DISTANCE + 1))

    # 3) Action-word boost — brand + "login"/"verify"/etc is a classic lure
    has_action_word = any(t in _ACTION_WORDS for t in tokens)
    if has_action_word and (keyword_hits or typosquat_hits):
        score += ACTION_WORD_BOOST

    return {
        "score": round(min(score, 1.0), 4),
        "matched_brands": sorted(matched_brands),
        "keyword_hits": sorted(set(keyword_hits)),
        "typosquat_hits": typosquat_hits,
        "has_action_word": has_action_word,
    }
