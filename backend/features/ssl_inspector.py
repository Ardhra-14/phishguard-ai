"""
SSL certificate inspector — Phase 2.

Opens a real TLS connection to the domain on port 443 and inspects the
leaf certificate: whether the handshake validated against trusted CAs,
issuer, days until expiry, and whether it's self-signed. Phishing sites
increasingly *do* have valid HTTPS (free CAs like Let's Encrypt made
"padlock = safe" advice obsolete years ago), but self-signed / expired /
freshly-issued certs are still a meaningful signal in combination with
other features.

`ssl.create_connection` + `SSLContext.wrap_socket` are blocking, so the
connection runs in a thread via `asyncio.to_thread`, wrapped in
`asyncio.wait_for` so a hanging handshake can't stall the scan pipeline.
"""
import asyncio
import socket
import ssl
from datetime import datetime, timezone

from core.config import settings

SSL_PORT = 443


def _parse_cert_date(value: str) -> datetime:
    # e.g. "Jun  1 12:00:00 2026 GMT" — format used by ssl.getpeercert()
    return datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)


def _inspect_validated_sync(domain: str) -> dict:
    """Handshake using a default (CA-validating) context. Raises ssl.SSLCertVerificationError
    if the cert is untrusted, self-signed, expired, or hostname-mismatched."""
    ctx = ssl.create_default_context()
    with socket.create_connection((domain, SSL_PORT), timeout=settings.SSL_TIMEOUT) as sock:
        with ctx.wrap_socket(sock, server_hostname=domain) as tls_sock:
            cert = tls_sock.getpeercert()

    issuer = dict(x[0] for x in cert.get("issuer", []))
    not_after = _parse_cert_date(cert["notAfter"])
    days_until_expiry = (not_after - datetime.now(timezone.utc)).days

    return {
        "ssl_valid": True,
        "ssl_self_signed": False,
        "ssl_issuer": issuer.get("organizationName") or issuer.get("commonName"),
        "ssl_days_until_expiry": days_until_expiry,
        "ssl_expired": days_until_expiry < 0,
    }


def _inspect_unvalidated_sync(domain: str) -> dict:
    """Fallback handshake with verification disabled, used only to distinguish
    'no cert / connection refused' from 'cert present but untrusted/self-signed'."""
    ctx = ssl._create_unverified_context()
    try:
        with socket.create_connection((domain, SSL_PORT), timeout=settings.SSL_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as tls_sock:
                der_cert = tls_sock.getpeercert(binary_form=True)
                cert = tls_sock.getpeercert()
    except (socket.error, ssl.SSLError, OSError):
        return {
            "ssl_valid": False,
            "ssl_self_signed": False,
            "ssl_issuer": None,
            "ssl_days_until_expiry": None,
            "ssl_expired": None,
        }

    issuer = dict(x[0] for x in cert.get("issuer", [])) if cert else {}
    subject = dict(x[0] for x in cert.get("subject", [])) if cert else {}
    self_signed = bool(issuer) and issuer == subject

    days_until_expiry = None
    if cert and cert.get("notAfter"):
        not_after = _parse_cert_date(cert["notAfter"])
        days_until_expiry = (not_after - datetime.now(timezone.utc)).days

    return {
        "ssl_valid": False,
        "ssl_self_signed": self_signed,
        "ssl_issuer": issuer.get("organizationName") or issuer.get("commonName"),
        "ssl_days_until_expiry": days_until_expiry,
        "ssl_expired": bool(days_until_expiry is not None and days_until_expiry < 0),
    }


def _inspect_sync(domain: str) -> dict:
    try:
        return _inspect_validated_sync(domain)
    except ssl.SSLCertVerificationError:
        return _inspect_unvalidated_sync(domain)
    except (socket.error, ssl.SSLError, OSError):
        return {
            "ssl_valid": False,
            "ssl_self_signed": False,
            "ssl_issuer": None,
            "ssl_days_until_expiry": None,
            "ssl_expired": None,
        }


async def inspect_ssl(domain: str) -> dict:
    """
    Inspect the TLS certificate presented by a domain on port 443.

    Returns:
        {
            "ssl_valid": bool,                    # trusted-CA handshake succeeded
            "ssl_self_signed": bool,
            "ssl_issuer": str | None,
            "ssl_days_until_expiry": int | None,
            "ssl_expired": bool | None,
        }

    A domain with no listener on 443 at all (common for phishing pages that
    only serve HTTP) returns ssl_valid=False with everything else None —
    that absence is itself a feature, not treated as an error.
    """
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_inspect_sync, domain),
            timeout=settings.SSL_TIMEOUT + 1,
        )
    except asyncio.TimeoutError:
        return {
            "ssl_valid": False,
            "ssl_self_signed": False,
            "ssl_issuer": None,
            "ssl_days_until_expiry": None,
            "ssl_expired": None,
        }
