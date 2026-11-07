"""Scope-first authorized reconnaissance MVP."""
import ipaddress
import json
import re
import socket
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

HOST = re.compile(r"^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$")

class PolicyError(Exception):
    pass

def normalize_host(value):
    try:
        host = value.strip().rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise PolicyError("Invalid hostname") from exc
    if not HOST.fullmatch(host):
        raise PolicyError("Invalid hostname: " + repr(host))
    return host

def matches(host, pattern):
    pattern = pattern.lower().rstrip(".")
    if pattern.startswith("*."):
        return host.endswith("." + normalize_host(pattern[2:]))
    return host == normalize_host(pattern)

@dataclass
class Policy:
    includes: list
    excludes: list
    active_http: bool = False
    approved: bool = False
    rps: float = 1.0
    max_targets: int = 100
    authorized_ip_cidrs: tuple = ()
    authorized_cname_suffixes: tuple = ()

    @classmethod
    def from_file(cls, path):
        data = json.loads(Path(path).read_text())
        rules = data.get("rules", {})
        scope = data["scope"]
        obj = cls(scope["include"], scope.get("exclude", []),
                  bool(rules.get("active_http", False)),
                  bool(rules.get("researcher_approved", False)),
                  float(rules.get("max_requests_per_second", 1)),
                  int(rules.get("max_targets", 100)),
                  tuple(rules.get("authorized_ip_cidrs", [])),
                  tuple(rules.get("authorized_cname_suffixes", [])))
        if not obj.includes or obj.rps <= 0 or not 1 <= obj.max_targets <= 10000:
            raise PolicyError("Invalid policy")
        for p in obj.includes + obj.excludes:
            normalize_host(p[2:] if p.startswith("*.") else p)
        for suffix in obj.authorized_cname_suffixes:
            normalize_host(suffix[2:] if suffix.startswith("*.") else suffix)
        for cidr in obj.authorized_ip_cidrs:
            network = ipaddress.ip_network(cidr, strict=False)
            if not network.is_global:
                raise PolicyError("Approved CIDR must be public")
        return obj

    def require(self, hostname, active=False):
        host = normalize_host(hostname)
        if not any(matches(host, p) for p in self.includes):
            raise PolicyError("Out of scope: " + host)
        if any(matches(host, p) for p in self.excludes):
            raise PolicyError("Excluded: " + host)
        if active and not (self.active_http and self.approved):
            raise PolicyError("Active check not authorized")
        return host

def public_ips(host):
    addresses = sorted({item[4][0] for item in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)})
    if not addresses or any(not ipaddress.ip_address(ip).is_global for ip in addresses):
        raise PolicyError("Non-public or unsafe DNS response")
    return addresses

def recommend(headers):
    h = {k.lower(): v for k, v in headers.items()}
    descriptions = {
        "strict-transport-security": "HSTS helps enforce HTTPS in browsers.",
        "content-security-policy": "CSP can reduce the impact of some browser injection attacks.",
        "x-content-type-options": "nosniff can reduce MIME-type confusion."
    }
    return [{"check": k, "observation": "Header not observed",
             "why": v, "next_step": "Review applicability; absence alone is not a vulnerability."}
            for k, v in descriptions.items() if k not in h]

def check_https(host, policy, approval_db=None, approval_id=None):
    host = policy.require(host, active=True)
    from .approvals import require_approval, audit_event
    from .ownership import check_ownership
    if approval_db is None or approval_id is None:
        raise PolicyError("Active check requires a persistent approval record")
    require_approval(approval_db, policy, approval_id, host)
    evidence = check_ownership(host, policy, public_ips(host))
    ip = evidence["approved_ips"][0]
    audit_event(approval_db, "cli", "active_probe_started", approval_id, host)
    destination = "[" + ip + "]" if ":" in ip else ip
    cmd = ["curl", "--silent", "--show-error", "--head", "--http1.1",
           "--proto", "=https", "--max-redirs", "0", "--max-time", "10",
           "--noproxy", "*", "--resolve", f"{host}:443:{destination}",
           "--output", "/dev/null", "--dump-header", "-",
           "--write-out", "\nPROBE:%{http_code}|%{remote_ip}|%{ssl_verify_result}\n",
           "https://" + host + "/"]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=13, check=False)
    if result.returncode:
        raise RuntimeError("HTTPS probe failed: curl exit " + str(result.returncode))
    marker = re.search(r"PROBE:(\d+)\|([^|]+)\|(\d+)", result.stdout)
    if not marker or marker.group(2) != ip or marker.group(3) != "0":
        raise PolicyError("Transport destination or TLS verification mismatch")
    blocks = re.split(r"\r?\n\r?\n", result.stdout.split("PROBE:")[0].strip())
    response = next((b for b in reversed(blocks) if b.startswith("HTTP/")), "")
    headers = {}
    for line in response.splitlines()[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip()] = v.strip()
    return {"status": int(marker.group(1)), "ip": ip, "headers": headers,
            "recommendations": recommend(headers), "ownership_evidence": evidence,
            "note": "HEAD / only; no redirects followed"}

def run(policy, targets, active=False, approval_db=None, approval_id=None):
    if active and not (policy.active_http and policy.approved):
        raise PolicyError("Active checks require explicit permission and approval")
    seen = set()
    results = []
    last = 0.0
    for target in targets:
        target = target.strip()
        if not target or target.startswith("#"):
            continue
        try:
            host = normalize_host(target)
            if host in seen:
                continue
            seen.add(host)
            policy.require(host, active)
            item = {"host": host, "scope": "allowed"}
            if active:
                wait = max(0, 1 / policy.rps - (time.monotonic() - last))
                if wait:
                    time.sleep(wait)
                last = time.monotonic()
                item["http"] = check_https(host, policy, approval_db, approval_id)
        except (PolicyError, RuntimeError, OSError, subprocess.TimeoutExpired) as exc:
            item = {"host": target, "scope": "rejected_or_failed", "reason": str(exc)}
        results.append(item)
        if len(results) >= policy.max_targets:
            break
    return results
