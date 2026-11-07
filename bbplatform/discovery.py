"""Passive certificate-transparency discovery. Never probes discovered hosts."""
import json
import urllib.parse
import urllib.request
from .core import normalize_host, PolicyError

def certificate_transparency(domain, policy, *, fetch=None, max_records=5000):
    """Query public CT records; discovered names remain candidates, not authorized assets."""
    domain = policy.require(domain)
    if fetch is None:
        def fetch(url):
            request = urllib.request.Request(url, headers={"User-Agent": "ScopeResearchMVP/0.2"})
            with urllib.request.urlopen(request, timeout=12) as response:
                if response.status != 200:
                    raise RuntimeError("CT provider error")
                data = response.read(2_000_001)
                if len(data) > 2_000_000:
                    raise RuntimeError("CT response too large")
                return json.loads(data)
    url = "https://crt.sh/?q=" + urllib.parse.quote("%." + domain, safe="") + "&output=json"
    records = fetch(url)
    if not isinstance(records, list) or len(records) > max_records:
        raise RuntimeError("Unexpected or oversized CT result")
    candidates = set()
    for entry in records:
        if not isinstance(entry, dict):
            continue
        for raw in str(entry.get("name_value", "")).splitlines():
            raw = raw.strip().lower()
            if raw.startswith("*."):
                raw = raw[2:]
            try:
                host = normalize_host(raw)
                if host == domain or host.endswith("." + domain):
                    candidates.add(host)
            except PolicyError:
                continue
    return [{"host": host, "scope": "candidate_allowed" if policy_allows(policy, host)
             else "candidate_excluded", "source": "certificate_transparency",
             "network_contacted": False} for host in sorted(candidates)]

def policy_allows(policy, host):
    try:
        policy.require(host)
        return True
    except PolicyError:
        return False
