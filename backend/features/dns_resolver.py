"""
DNS resolver — Phase 2.

Async DNS lookups (A, AAAA, MX) for a domain using dnspython's asyncresolver.
A domain that fails to resolve at all is a strong phishing signal (short-lived
throwaway infrastructure); a domain with no MX record but a live A record is
common for pure credential-harvesting pages that never receive mail.

Network errors (NXDOMAIN, timeout, no nameservers, etc.) are all treated as
"does not resolve" rather than raised — this module must never crash the
scan pipeline just because a domain is dead or unreachable.
"""
import dns.asyncresolver
import dns.resolver
import dns.exception

from core.config import settings

_resolver = dns.asyncresolver.Resolver()
_resolver.lifetime = settings.DNS_TIMEOUT
_resolver.timeout = settings.DNS_TIMEOUT


async def _query(domain: str, record_type: str) -> list[str]:
    try:
        answer = await _resolver.resolve(domain, record_type)
        return [rdata.to_text() for rdata in answer]
    except (
        dns.resolver.NXDOMAIN,
        dns.resolver.NoAnswer,
        dns.resolver.NoNameservers,
        dns.exception.Timeout,
    ):
        return []


async def resolve_dns(domain: str) -> dict:
    """
    Resolve A, AAAA, and MX records for a domain.

    Returns:
        {
            "dns_resolves": bool,             # True if any A or AAAA record found
            "dns_a_record_count": int,
            "dns_has_aaaa": bool,
            "dns_has_mx": bool,
            "dns_resolved_ips": list[str],
        }
    """
    a_records = await _query(domain, "A")
    aaaa_records = await _query(domain, "AAAA")
    mx_records = await _query(domain, "MX")

    return {
        "dns_resolves": bool(a_records or aaaa_records),
        "dns_a_record_count": len(a_records),
        "dns_has_aaaa": bool(aaaa_records),
        "dns_has_mx": bool(mx_records),
        "dns_resolved_ips": a_records + aaaa_records,
    }
