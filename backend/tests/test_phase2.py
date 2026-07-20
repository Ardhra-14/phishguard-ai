"""
Phase 2 tests — DNS resolver, WHOIS lookup, SSL inspector, and their
integration into FeaturePipeline.

All network calls are mocked. These modules talk to real DNS servers,
WHOIS servers, and remote hosts on port 443 in production, but tests must
stay deterministic and runnable with zero network access (CI, sandboxes,
offline dev) — same offline-determinism principle test_phase1.py already
follows for the lexical/brand/TLD/IDN modules.

Run with:  pytest tests/test_phase2.py -v
"""
from datetime import datetime, timedelta, timezone
from unittest.mock import patch, AsyncMock

import dns.resolver
import dns.exception
import ssl as ssl_module

from features.dns_resolver import resolve_dns
from features.whois_lookup import lookup_whois, RECENTLY_REGISTERED_THRESHOLD_DAYS
from features.ssl_inspector import (
    inspect_ssl,
    _inspect_sync,
    _inspect_validated_sync,
    _inspect_unvalidated_sync,
    _parse_cert_date,
)
from features.pipeline import FeaturePipeline


# ── dns_resolver.py ────────────────────────────────────────────────────────

class _FakeRData:
    def __init__(self, text):
        self._text = text

    def to_text(self):
        return self._text


async def test_resolve_dns_resolves_with_a_and_mx():
    async def fake_resolve(domain, record_type):
        if record_type == "A":
            return [_FakeRData("93.184.216.34")]
        if record_type == "MX":
            return [_FakeRData("10 mail.example.com.")]
        raise dns.resolver.NoAnswer

    with patch("features.dns_resolver._resolver.resolve", new=AsyncMock(side_effect=fake_resolve)):
        result = await resolve_dns("example.com")

    assert result["dns_resolves"] is True
    assert result["dns_a_record_count"] == 1
    assert result["dns_has_mx"] is True
    assert result["dns_has_aaaa"] is False
    assert result["dns_resolved_ips"] == ["93.184.216.34"]


async def test_resolve_dns_nxdomain_does_not_raise():
    async def fake_resolve(domain, record_type):
        raise dns.resolver.NXDOMAIN

    with patch("features.dns_resolver._resolver.resolve", new=AsyncMock(side_effect=fake_resolve)):
        result = await resolve_dns("this-domain-does-not-exist-xyz.invalid")

    assert result["dns_resolves"] is False
    assert result["dns_a_record_count"] == 0
    assert result["dns_resolved_ips"] == []


async def test_resolve_dns_timeout_does_not_raise():
    async def fake_resolve(domain, record_type):
        raise dns.exception.Timeout

    with patch("features.dns_resolver._resolver.resolve", new=AsyncMock(side_effect=fake_resolve)):
        result = await resolve_dns("slow-server.example")

    assert result["dns_resolves"] is False


async def test_resolve_dns_aaaa_only_still_resolves():
    async def fake_resolve(domain, record_type):
        if record_type == "AAAA":
            return [_FakeRData("2606:2800:220:1:248:1893:25c8:1946")]
        raise dns.resolver.NoAnswer

    with patch("features.dns_resolver._resolver.resolve", new=AsyncMock(side_effect=fake_resolve)):
        result = await resolve_dns("ipv6-only.example")

    assert result["dns_resolves"] is True
    assert result["dns_has_aaaa"] is True
    assert result["dns_a_record_count"] == 0


# ── whois_lookup.py ─────────────────────────────────────────────────────────

class _FakeWhoisRecord:
    def __init__(self, creation_date=None, registrar=None, org=None):
        self.creation_date = creation_date
        self.registrar = registrar
        self.org = org


async def test_lookup_whois_computes_domain_age():
    created = datetime.now(timezone.utc) - timedelta(days=3650)
    fake_record = _FakeWhoisRecord(creation_date=created, registrar="MarkMonitor Inc.")

    with patch("features.whois_lookup.pywhois.whois", return_value=fake_record):
        result = await lookup_whois("onlinesbi.com")

    assert result["whois_found"] is True
    assert result["whois_domain_age_days"] == 3650
    assert result["whois_registrar"] == "MarkMonitor Inc."
    assert result["whois_recently_registered"] is False


async def test_lookup_whois_flags_recently_registered_domain():
    created = datetime.now(timezone.utc) - timedelta(days=2)
    fake_record = _FakeWhoisRecord(creation_date=created, registrar="NameCheap")

    with patch("features.whois_lookup.pywhois.whois", return_value=fake_record):
        result = await lookup_whois("secure-sbi-login-verify.xyz")

    assert result["whois_domain_age_days"] == 2
    assert result["whois_domain_age_days"] < RECENTLY_REGISTERED_THRESHOLD_DAYS
    assert result["whois_recently_registered"] is True


async def test_lookup_whois_handles_list_valued_creation_date():
    """Some registries return creation_date as a list of duplicate/near-duplicate
    dates instead of a single datetime — must normalize to the first entry."""
    created = datetime.now(timezone.utc) - timedelta(days=100)
    fake_record = _FakeWhoisRecord(creation_date=[created, created], registrar=["Registrar A", "Registrar A"])

    with patch("features.whois_lookup.pywhois.whois", return_value=fake_record):
        result = await lookup_whois("example.com")

    assert result["whois_domain_age_days"] == 100
    assert result["whois_registrar"] == "Registrar A"


async def test_lookup_whois_privacy_protected_detection():
    created = datetime.now(timezone.utc) - timedelta(days=400)
    fake_record = _FakeWhoisRecord(creation_date=created, registrar="NameCheap", org="WhoisGuard Protected")

    with patch("features.whois_lookup.pywhois.whois", return_value=fake_record):
        result = await lookup_whois("example.com")

    assert result["whois_privacy_protected"] is True


async def test_lookup_whois_failure_returns_safe_defaults_not_exception():
    with patch("features.whois_lookup.pywhois.whois", side_effect=Exception("no whois server for this TLD")):
        result = await lookup_whois("some-domain.unknowntld")

    assert result["whois_found"] is False
    assert result["whois_domain_age_days"] is None
    assert result["whois_recently_registered"] is False


async def test_lookup_whois_retries_once_on_transient_dns_error():
    """Simulates the Docker embedded-DNS-proxy flakiness observed in testing:
    socket.gaierror on the first attempt, success on the retry."""
    import socket as socket_module

    created = datetime.now(timezone.utc) - timedelta(days=9000)
    fake_record = _FakeWhoisRecord(creation_date=created, registrar="MarkMonitor Inc.")
    call_count = {"n": 0}

    def flaky_whois(domain):
        call_count["n"] += 1
        if call_count["n"] == 1:
            raise socket_module.gaierror("No address associated with hostname")
        return fake_record

    with patch("features.whois_lookup.pywhois.whois", side_effect=flaky_whois), \
         patch("features.whois_lookup.time.sleep"):  # skip the real backoff delay in tests
        result = await lookup_whois("google.com")

    assert call_count["n"] == 2
    assert result["whois_found"] is True
    assert result["whois_registrar"] == "MarkMonitor Inc."


async def test_lookup_whois_gives_up_after_max_attempts_still_transient():
    import socket as socket_module

    with patch("features.whois_lookup.pywhois.whois",
               side_effect=socket_module.gaierror("No address associated with hostname")), \
         patch("features.whois_lookup.time.sleep"):
        result = await lookup_whois("google.com")

    assert result["whois_found"] is False
    assert result["whois_domain_age_days"] is None


# ── ssl_inspector.py ─────────────────────────────────────────────────────────

def test_parse_cert_date():
    parsed = _parse_cert_date("Jan  1 00:00:00 2099 GMT")
    assert parsed.year == 2099
    assert parsed.tzinfo is not None


class _FakeTLSSocket:
    def __init__(self, cert, der=b"fake-der-bytes"):
        self._cert = cert
        self._der = der

    def getpeercert(self, binary_form=False):
        return self._der if binary_form else self._cert

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _FakeRawSocket:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _FakeContext:
    def __init__(self, cert=None, raise_verification_error=False):
        self._cert = cert
        self._raise = raise_verification_error

    def wrap_socket(self, sock, server_hostname=None):
        if self._raise:
            raise ssl_module.SSLCertVerificationError("certificate verify failed: self signed certificate")
        return _FakeTLSSocket(self._cert)


def _future_cert(org="Let's Encrypt", days_ahead=60):
    not_after = (datetime.now(timezone.utc) + timedelta(days=days_ahead)).strftime("%b %d %H:%M:%S %Y GMT")
    return {"issuer": [[("organizationName", org)]], "notAfter": not_after}


def test_inspect_validated_sync_returns_valid_cert_details():
    cert = _future_cert(org="Let's Encrypt", days_ahead=60)
    with patch("features.ssl_inspector.socket.create_connection", return_value=_FakeRawSocket()), \
         patch("features.ssl_inspector.ssl.create_default_context", return_value=_FakeContext(cert=cert)):
        result = _inspect_validated_sync("example.com")

    assert result["ssl_valid"] is True
    assert result["ssl_self_signed"] is False
    assert result["ssl_issuer"] == "Let's Encrypt"
    assert result["ssl_days_until_expiry"] in (59, 60)
    assert result["ssl_expired"] is False


def test_inspect_unvalidated_sync_detects_self_signed():
    subject_issuer = [[("organizationName", "MyOwnCA")]]
    cert = {
        "issuer": subject_issuer,
        "subject": subject_issuer,
        "notAfter": (datetime.now(timezone.utc) + timedelta(days=30)).strftime("%b %d %H:%M:%S %Y GMT"),
    }
    with patch("features.ssl_inspector.socket.create_connection", return_value=_FakeRawSocket()), \
         patch("features.ssl_inspector.ssl._create_unverified_context", return_value=_FakeContext(cert=cert)):
        result = _inspect_unvalidated_sync("self-signed.example")

    assert result["ssl_valid"] is False
    assert result["ssl_self_signed"] is True


def test_inspect_sync_falls_back_on_verification_error():
    subject_issuer = [[("organizationName", "PhishCA")]]
    cert = {
        "issuer": subject_issuer,
        "subject": subject_issuer,
        "notAfter": (datetime.now(timezone.utc) + timedelta(days=10)).strftime("%b %d %H:%M:%S %Y GMT"),
    }
    with patch("features.ssl_inspector.socket.create_connection", return_value=_FakeRawSocket()), \
         patch("features.ssl_inspector.ssl.create_default_context", return_value=_FakeContext(raise_verification_error=True)), \
         patch("features.ssl_inspector.ssl._create_unverified_context", return_value=_FakeContext(cert=cert)):
        result = _inspect_sync("self-signed.example")

    assert result["ssl_valid"] is False
    assert result["ssl_self_signed"] is True
    assert result["ssl_issuer"] == "PhishCA"


def test_inspect_sync_no_listener_on_443_returns_safe_defaults():
    with patch("features.ssl_inspector.socket.create_connection", side_effect=OSError("connection refused")):
        result = _inspect_sync("http-only.example")

    assert result["ssl_valid"] is False
    assert result["ssl_self_signed"] is False
    assert result["ssl_issuer"] is None
    assert result["ssl_days_until_expiry"] is None


async def test_inspect_ssl_async_wrapper_returns_sync_result():
    canned = {
        "ssl_valid": True,
        "ssl_self_signed": False,
        "ssl_issuer": "DigiCert",
        "ssl_days_until_expiry": 90,
        "ssl_expired": False,
    }
    with patch("features.ssl_inspector.asyncio.to_thread", new=AsyncMock(return_value=canned)):
        result = await inspect_ssl("example.com")

    assert result == canned


# ── pipeline.py integration ──────────────────────────────────────────────────

async def test_pipeline_includes_populated_phase2_features():
    with patch("features.pipeline.resolve_dns", new=AsyncMock(return_value={
            "dns_resolves": True, "dns_a_record_count": 2,
            "dns_has_aaaa": True, "dns_has_mx": True, "dns_resolved_ips": ["1.2.3.4"],
        })), \
         patch("features.pipeline.lookup_whois", new=AsyncMock(return_value={
            "whois_found": True, "whois_domain_age_days": 5000,
            "whois_recently_registered": False, "whois_privacy_protected": False,
        })), \
         patch("features.pipeline.inspect_ssl", new=AsyncMock(return_value={
            "ssl_valid": True, "ssl_self_signed": False,
            "ssl_issuer": "DigiCert", "ssl_days_until_expiry": 120, "ssl_expired": False,
        })):
        pipeline = FeaturePipeline()
        features = await pipeline.extract("https://www.onlinesbi.com")

    assert features["dns_resolves"] is True
    assert features["whois_domain_age_days"] == 5000
    assert features["ssl_valid"] is True
    assert features["whois_recently_registered"] == 0
    # Phase 4 keys remain unpopulated stubs until that phase is built
    assert features["visual_similarity_score"] is None
    assert features["dom_credential_form_detected"] is None


async def test_pipeline_flags_freshly_registered_no_dns_domain_as_riskier_signals():
    """A freshly-registered domain that doesn't even resolve yet (parked /
    not-yet-live phishing infra) should carry the corresponding risk flags,
    independent of whatever the aggregate lexical score says."""
    with patch("features.pipeline.resolve_dns", new=AsyncMock(return_value={
            "dns_resolves": False, "dns_a_record_count": 0,
            "dns_has_aaaa": False, "dns_has_mx": False, "dns_resolved_ips": [],
        })), \
         patch("features.pipeline.lookup_whois", new=AsyncMock(return_value={
            "whois_found": True, "whois_domain_age_days": 1,
            "whois_recently_registered": True, "whois_privacy_protected": True,
        })), \
         patch("features.pipeline.inspect_ssl", new=AsyncMock(return_value={
            "ssl_valid": False, "ssl_self_signed": False,
            "ssl_issuer": None, "ssl_days_until_expiry": None, "ssl_expired": None,
        })):
        pipeline = FeaturePipeline()
        features = await pipeline.extract("https://freshly-registered-phish.xyz")

    assert features["dns_resolves"] is False
    assert features["whois_recently_registered"] == 1
    assert features["whois_privacy_protected"] == 1
    assert features["ssl_valid"] is False
