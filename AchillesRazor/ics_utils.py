"""Shared helpers for AchillesRazor checks."""

import dns.resolver


def safe_resolve(name, rdtype="A", timeout=2.0, lifetime=3.0):
    """Resolve a DNS record with an explicitly enforced timeout.

    dnspython's module-level dns.resolver.resolve() uses a shared default
    resolver whose effective timeout depends on system config and can block
    far longer than expected against unreachable or filtering nameservers
    (common on segmented OT networks). This always builds a fresh Resolver
    with an explicit per-query timeout and total lifetime instead.

    Returns a list of answers on success, an empty list when the resolver
    confirms no such record exists (NoAnswer), and None on any other
    failure (timeout, NXDOMAIN, unreachable nameserver, etc.) so callers can
    tell "no record" apart from "couldn't check".
    """
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = lifetime
        return list(resolver.resolve(name, rdtype))
    except dns.resolver.NoAnswer:
        return []
    except Exception:
        return None
