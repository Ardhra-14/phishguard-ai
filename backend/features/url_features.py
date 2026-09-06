"""
URL lexical feature extractor — Phase 1.

Extracts 12 structural/lexical features from a URL. These are pure
string-analysis signals (no network calls) that correlate strongly with
phishing URLs: excessive length, hyphenation, digit-stuffing, high entropy,
deep subdomains, missing HTTPS, raw-IP hosts, etc.
"""
import ipaddress
import math
import re
from collections import Counter
from urllib.parse import urlparse

_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _shannon_entropy(s: str) -> float:
    """Shannon entropy of a string, in bits per character."""
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _is_ip_host(host: str) -> bool:
    host = host.split(":")[0]  # strip port if present
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return bool(_IP_RE.match(host))


def extract_url_features(url: str) -> dict:
    """
    Extract 12 lexical/structural features from a URL.

    Returns a dict with keys:
        url_length, hyphen_count, dot_count, digit_count, entropy,
        subdomain_depth, has_https, is_ip_address, has_at_symbol,
        path_length, query_param_count, special_char_count
    """
    parsed = urlparse(url if "://" in url else f"https://{url}")
    host = parsed.netloc.split("@")[-1]      # drop userinfo (user:pass@) if present
    host_no_port = host.split(":")[0]
    labels = [label for label in host_no_port.split(".") if label]

    # Rough heuristic: everything before the last two labels counts as
    # subdomain depth, e.g. "a.b.example.com" -> depth 2.
    subdomain_depth = max(len(labels) - 2, 0)

    special_chars = re.findall(r"[^a-zA-Z0-9.\-/:]", url)

    # path_length fix (Phase 3.5): urlparse("https://x.com/").path == "/"
    # (len 1) vs urlparse("https://x.com").path == "" (len 0) -- these are
    # semantically the same "bare homepage" case, but a raw len() on the
    # parsed path treated them as different by exactly 1. That off-by-one
    # turned out to correlate strongly with URL *source* (OpenPhish-reported
    # phishing URLs almost always keep a trailing slash; legit URLs resolved
    # via aiohttp's resp.url didn't consistently), not with actual phishing
    # signal -- confirmed via SHAP analysis showing path_length dominating
    # despite near-zero native feature_importances_, and 62.4% of phishing
    # URLs having a bare/root path per raw urlparse() check while the
    # feature showed 0% at path_length==0 for that same class. Stripping a
    # single trailing "/" before measuring length treats "/", "", and
    # "/login/" vs "/login" consistently. See
    # backend/data/phase3_5_path_length_check.md for the full investigation.
    raw_path = parsed.path or ""
    normalized_path = raw_path[:-1] if raw_path.endswith("/") and len(raw_path) > 1 else raw_path
    if normalized_path == "/":
        normalized_path = ""

    return {
        "url_length": len(url),
        "hyphen_count": host_no_port.count("-"),
        "dot_count": host_no_port.count("."),
        "digit_count": sum(c.isdigit() for c in host_no_port),
        "entropy": round(_shannon_entropy(host_no_port), 4),
        "subdomain_depth": subdomain_depth,
        "has_https": int(parsed.scheme == "https"),
        "is_ip_address": int(_is_ip_host(host_no_port)),
        "has_at_symbol": int("@" in url),
        "path_length": len(normalized_path),
        "query_param_count": len(parsed.query.split("&")) if parsed.query else 0,
        "special_char_count": len(special_chars),
    }