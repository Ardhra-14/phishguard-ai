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
        "path_length": len(parsed.path or ""),
        "query_param_count": len(parsed.query.split("&")) if parsed.query else 0,
        "special_char_count": len(special_chars),
    }
