"""
TLD risk scorer — Phase 1.

Looks up a domain's TLD (handling multi-label suffixes like .gov.in,
.co.in) against a curated risk table. Implemented without a live
public-suffix-list fetch so it stays deterministic and works offline.
"""
import json
from pathlib import Path
from urllib.parse import urlparse

_DATA_PATH = Path(__file__).resolve().parent.parent / "data" / "tld_risk_table.json"

with open(_DATA_PATH, "r", encoding="utf-8") as f:
    _TLD_RISK: dict[str, float] = json.load(f)

# Multi-label suffixes (containing a dot), longest first so "gov.in" is
# matched before falling back to the single label "in".
_MULTI_LABEL_SUFFIXES = sorted(
    (tld for tld in _TLD_RISK if "." in tld), key=len, reverse=True
)

DEFAULT_UNKNOWN_TLD_RISK = 0.5


def _extract_host(domain: str) -> str:
    if "://" in domain:
        domain = urlparse(domain).netloc
    domain = domain.split("@")[-1].split(":")[0]
    if domain.startswith("www."):
        domain = domain[4:]
    return domain.lower()


def get_tld(domain: str) -> str:
    """Return the risk-table TLD key that best matches this domain."""
    host = _extract_host(domain)
    for suffix in _MULTI_LABEL_SUFFIXES:
        if host == suffix or host.endswith("." + suffix):
            return suffix
    labels = host.split(".")
    return labels[-1] if labels else host


def score_tld(domain: str) -> dict:
    """
    Returns:
        {"tld": str, "risk": float 0-1, "known": bool}
    """
    tld = get_tld(domain)
    if tld in _TLD_RISK:
        return {"tld": tld, "risk": _TLD_RISK[tld], "known": True}
    return {"tld": tld, "risk": DEFAULT_UNKNOWN_TLD_RISK, "known": False}
