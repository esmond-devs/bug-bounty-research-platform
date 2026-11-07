# Identity, audit integrity and authorization evidence (v0.4)

This is a **local prototype**. It is not production-grade identity management, immutable auditing, or legal ownership verification.

## Bootstrap authenticated accounts

```bash
pip install -r requirements.txt
python manage_users.py --username researcher1 --role researcher
python manage_users.py --username reviewer1 --role reviewer
python dashboard.py --policy examples/policy.json
```

Each command prompts for a password (minimum 14 characters). Accounts use salted scrypt password hashes and server-side random session tokens stored as SHA-256 digests. Sessions expire after 8 hours. The dashboard binds only to localhost. A different authenticated reviewer must approve a research request or submitted ownership evidence.

## Evidence workflow

The researcher submits the exact hostname, program identifier, and a reference to independently verifiable program authorization (such as a program scope statement or signed authorization record). The submission snapshots configured authorized IP networks and CNAME suffixes. An independent reviewer reviews the source and marks the evidence verified or rejected; verification expires after 24 hours. **The software does not automatically verify the legal authority of a program or infrastructure owner.** It records a human attestation.

Active CLI mode requires: a specific approval record; matching current policy; a current reviewed evidence record for the exact hostname, program and network/CNAME policy; and successful live DNS CNAME/IP validation. Only low-impact HTTPS HEAD is implemented.

## Hash-linked audit records

`bbplatform/audit_chain.py` creates a hash chain over selected dashboard security events. Run `verify(db, expected_head)` to detect local modifications relative to an independently stored trusted head. Without an independently anchored head, an administrator who can rewrite the SQLite database can also recompute the chain; this is **not immutable storage**. The older audit table remains available for backward compatibility. Store periodic head hashes outside this host (e.g., immutable object storage with retention lock), add database permissions, and migrate to a centralized event service before production.

## Limitations

- No MFA, account lockout, password reset, SSO, HTTPS remote serving, or hardened reverse proxy.
- No cryptographic program authorization signatures or independent registrar/cloud ownership attestation.
- No shared tenancy isolation or cross-process transactional audit guarantees.
- Do not expose the localhost dashboard on the internet.
- No broader automated scanning is enabled.
