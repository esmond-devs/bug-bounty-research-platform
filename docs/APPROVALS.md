# Researcher approvals and ownership attestation

This is a **local prototype**, not a secure multi-user identity or ownership verification service.

## Dashboard
Start `python dashboard.py --policy examples/policy.json`. It binds to 127.0.0.1 and displays a request queue, approve/reject actions, and recent audit events. Requests require a hostname, requester, and justification. Approvals expire in 24 hours by default. A different reviewer label is required, but labels are not authenticated identities. The dashboard uses a per-process anti-CSRF token, Origin checks, and local binding; do not expose it on a public interface or share it through a reverse proxy.

SQLite state defaults to `state/approvals.sqlite3`. It is excluded from Git. Audit entries are append-only at the application layer, but a local administrator can edit the SQLite database. For production, use authenticated roles, append-only external audit storage, approval signatures, and revocation.

## Active checks
Install `pip install -r requirements.txt`. Explicitly configure `active_http`, `researcher_approved`, `authorized_ip_cidrs`, and `authorized_cname_suffixes` based on **documented program authorization and infrastructure ownership**. Then run:

```bash
python cli.py --policy my-policy.json --targets my-targets.txt --active --approval-db state/approvals.sqlite3 --approval-id 1
```

The approval must be for the exact target hostname, be unexpired, and match the current policy fingerprint. Every DNS CNAME hop must be in the explicitly approved list; all resolved public IPs must fall in approved networks. The probe pins its destination and verifies TLS. If DNS cannot be verified, it fails closed.

**Caution:** A CNAME or IP address alone does not establish legal ownership. Approval labels are not authenticated, DNS may change between checks, and shared hosting/CDNs need explicit program permission. Broader scanning remains disabled. Only HTTPS HEAD metadata checks are supported.
