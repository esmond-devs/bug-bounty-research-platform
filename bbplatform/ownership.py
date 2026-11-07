"""Fail-closed CNAME and network ownership checks.

DNS alone never proves legal ownership; this validates declared infrastructure
against policy-provided evidence and must be paired with program authorization.
"""
import ipaddress
from .core import PolicyError, normalize_host, matches
from .guard import authorized_addresses

def resolve_chain(host, resolver=None, max_hops=8):
    """Return terminal name and CNAME chain; require dnspython for live lookups."""
    if resolver is None:
        try:
            import dns.resolver
        except ImportError as exc:
            raise PolicyError("Install dnspython to validate CNAME chains") from exc
        resolver = dns.resolver.resolve
    current = normalize_host(host)
    seen = set()
    chain = [current]
    for _ in range(max_hops):
        if current in seen:
            raise PolicyError("CNAME cycle")
        seen.add(current)
        try:
            answers = resolver(current, "CNAME")
        except Exception as exc:
            # NXDOMAIN / timeouts / unexpected errors must not be treated as no CNAME.
            if exc.__class__.__name__ == "NoAnswer":
                return chain
            raise PolicyError("Unable to verify CNAME chain: " + exc.__class__.__name__) from exc
        values = [normalize_host(str(a.target)) for a in answers]
        if len(values) != 1:
            raise PolicyError("Ambiguous CNAME chain")
        current = values[0]
        chain.append(current)
    raise PolicyError("CNAME chain exceeds limit")

def check_ownership(host, policy, addresses, *, resolver=None):
    """Every CNAME must be declared; all resolved IPs must be explicitly allowed."""
    host = policy.require(host, active=True)
    chain = resolve_chain(host, resolver=resolver)
    authorized = getattr(policy, "authorized_cname_suffixes", ())
    for name in chain[1:]:
        if not any(matches(name, p) for p in authorized):
            raise PolicyError("CNAME target not explicitly authorized: " + name)
    ips = authorized_addresses(addresses, policy.authorized_ip_cidrs)
    return {"chain": chain, "approved_ips": ips,
            "note": "Policy attestation only; independent ownership evidence required"}
