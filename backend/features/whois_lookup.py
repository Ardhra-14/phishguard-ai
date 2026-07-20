"""
WHOIS lookup — Phase 2.

Domain-age is one of the strongest phishing signals available: attackers
overwhelmingly register throwaway domains days (sometimes hours) before a
campaign and abandon them shortly after. `python-whois` is a blocking
library with no native asyncio support, so the lookup runs in a thread via
`asyncio.to_thread` and is wrapped in `asyncio.wait_for` so a slow or
non-responsive WHOIS server can never stall the scan pipeline.

Retries a couple of times on transient network/DNS errors before giving up:
`python-whois` resolves WHOIS server hostnames (e.g. whois.iana.org) via
plain `socket.gethostbyname`, which goes through Docker's embedded DNS
proxy (127.0.0.11) — that proxy occasionally returns a spurious
`socket.gaierror` for a hostname that resolves fine a moment later
(observed in testing: 1 failure out of ~4 consecutive lookups). A single
retry is enough to absorb that without masking a real, persistent failure.
"""
import asyncio
import socket
import time
from datetime import datetime, timezone

import whois as pywhois

from core.config import settings

# Domains registered more recently than this are treated as a strong
# standalone risk signal, independent of whatever the ML model later learns.
RECENTLY_REGISTERED_THRESHOLD_DAYS = 30

# Transient-failure retry policy for the WHOIS network call itself.
MAX_ATTEMPTS = 2
RETRY_DELAY_SECONDS = 0.5


def _first(value):
    """python-whois sometimes returns a list of dates/registrars instead of
    a single value, depending on the registry. Normalize to a single item."""
    if isinstance(value, list):
        return value[0] if value else None
    return value


def _to_utc(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _lookup_sync(domain: str) -> dict:
    last_error = None
    record = None

    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            record = pywhois.whois(domain)
            break
        except (socket.gaierror, socket.timeout, ConnectionError) as exc:
            # Transient DNS/connection hiccup resolving the WHOIS server
            # itself — worth one retry before treating it as "not found".
            last_error = exc
            if attempt < MAX_ATTEMPTS:
                time.sleep(RETRY_DELAY_SECONDS)

    if record is None:
        raise last_error

    creation_date = _first(record.creation_date)
    registrar = _first(record.registrar)
    privacy_terms = ("privacy", "redacted", "whoisguard", "proxy")
    registrant = str(_first(getattr(record, "org", None)) or "").lower()

    age_days = None
    if isinstance(creation_date, datetime):
        age_days = (datetime.now(timezone.utc) - _to_utc(creation_date)).days

    return {
        "whois_found": creation_date is not None or registrar is not None,
        "whois_domain_age_days": age_days,
        "whois_registrar": registrar,
        "whois_recently_registered": bool(
            age_days is not None and age_days < RECENTLY_REGISTERED_THRESHOLD_DAYS
        ),
        "whois_privacy_protected": any(term in registrant for term in privacy_terms),
    }


async def lookup_whois(domain: str) -> dict:
    """
    Look up WHOIS registration data for a domain.

    Returns:
        {
            "whois_found": bool,
            "whois_domain_age_days": int | None,
            "whois_registrar": str | None,
            "whois_recently_registered": bool,   # age < 30 days
            "whois_privacy_protected": bool,
        }

    Any failure (no WHOIS server for the TLD, network error, timeout,
    unparsable response) yields the same "not found" shape rather than
    raising — a missing WHOIS record is itself a mild risk signal, not
    a pipeline error.
    """
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_lookup_sync, domain),
            timeout=settings.WHOIS_TIMEOUT,
        )
    except Exception:
        return {
            "whois_found": False,
            "whois_domain_age_days": None,
            "whois_registrar": None,
            "whois_recently_registered": False,
            "whois_privacy_protected": False,
        }
