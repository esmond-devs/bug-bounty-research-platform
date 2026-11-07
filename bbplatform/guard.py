"""Conservative network guard for active HTTPS checks."""
import ipaddress
from .core import PolicyError

def authorized_addresses(addresses, allowed_cidrs):
    """Require ALL DNS answers to belong to explicitly approved public networks."""
    if not allowed_cidrs:
        raise PolicyError("Active network access denied: no authorized IP CIDRs configured")
    networks = [ipaddress.ip_network(cidr, strict=False) for cidr in allowed_cidrs]
    if not addresses:
        raise PolicyError("No DNS addresses")
    for raw in addresses:
        ip = ipaddress.ip_address(raw)
        if not ip.is_global or not any(ip in network for network in networks):
            raise PolicyError("DNS answer outside approved public IP networks")
    return list(addresses)
