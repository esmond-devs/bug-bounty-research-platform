# Bug Bounty Security Research Platform

**Scope-first authorized reconnaissance and educational security research — Python CLI + local dashboard MVP (v0.4).**

This repository contains an early prototype, not yet a production-ready bug bounty automation service. It validates user-provided target hostnames against explicit include/exclude policies and optionally performs approved, low-impact HTTPS HEAD checks. Results are saved as JSON, with explanations for missing HTTP security headers.

## Local interactive dashboard

```bash
python dashboard.py --policy examples/policy.json
```

Open http://127.0.0.1:8765. Enter an authorized root domain and select **Discover CT records**. The dashboard queries the public certificate-transparency index (crt.sh) and displays in-scope and excluded candidate names. It does **not** contact discovered hosts, run active checks, or persist findings between restarts. CT queries send the root domain to a third-party service; confirm this is permitted by your program.

## Stronger active-check requirements

Active checks now additionally require `authorized_ip_cidrs` in policy rules, containing explicitly approved **public** destination networks. Example: `"authorized_ip_cidrs": ["203.0.113.0/24"]` is documentation-only (reserved IPs will be rejected). Do not use a broad cloud provider range merely because a hostname resolves into it. Without approved networks, active checks fail closed. The new ownership guard verifies every DNS CNAME hop against explicit allowed suffixes and requires every resolved IP to match approved networks. This is **policy attestation**, not independent legal ownership verification.

## Authenticated accounts, evidence and audit integrity

Create local researcher and reviewer accounts with `python manage_users.py --username researcher1 --role researcher` and `python manage_users.py --username reviewer1 --role reviewer` (password prompts). Dashboard sign-in is required; role-based review actions use the authenticated account. Evidence records require an independent review and expire. Selected security events are recorded in a hash-linked audit chain; **external anchoring is required for tamper-evidence against database administrators**. See [identity, evidence and audit guide](docs/IDENTITY_AND_EVIDENCE.md).

## Researcher approval workflow

The local dashboard now includes an **approval queue**, approve/reject controls, and a SQLite audit timeline. Requesters provide an exact hostname and justification; a different reviewer label must approve the request, which expires after 24 hours. The CLI requires `--approval-db` and `--approval-id` in active mode. Approval records are bound to a fingerprint of the program policy. Reviewer actions now require a locally authenticated reviewer or admin account. This does not provide production SSO/MFA. See [approval and infrastructure documentation](docs/APPROVALS.md).

## Requirements
Python 3.10+; curl (for optional HTTPS checks). Install `pip install -r requirements.txt` for CNAME validation.

## Quick start
```bash
python -m unittest discover -s tests -v
python cli.py --policy examples/policy.json --targets examples/targets.txt --output results.json
```

This default run **does not send network requests**. Review the output and scope decisions before doing any active work.

To enable an authorized HTTPS check, edit a copy of the policy to set `active_http` and `researcher_approved` to `true`, after independently verifying the program permits automation and the specific target. Then add `--active --approval-db state/approvals.sqlite3 --approval-id <approved-request-id>` to the CLI. The checker only sends HTTPS HEAD to the root path, pins the resolved public IP, verifies TLS, and does not follow redirects. A scoped hostname is **not** sufficient proof of permission to probe third-party infrastructure.

## Documentation
- [Architecture](docs/ARCHITECTURE.md)
- [Security model and limitations](docs/SECURITY_MODEL.md)
- [Roadmap](docs/ROADMAP.md)
- [Contributing](CONTRIBUTING.md)

## Current capabilities
- Exact and wildcard hostname scope matching, with exclusions taking precedence
- Passive certificate-transparency candidate discovery and local dashboard
- JSON scope decisions and optional HTTPS response metadata
- Conservative active-mode approval flags and sequential request pacing
- Evidence-based educational security-header recommendations

## Not yet implemented
Additional passive discovery sources, independent third-party ownership verification, authenticated reviewer identities, tamper-evident audit storage, robust DNS rebinding defenses, distributed quotas, public multi-user UI, API, LLM recommendation engine, and advanced tool orchestration.

**Do not use this prototype against targets without explicit authorization.** Missing headers are not confirmed vulnerabilities. Avoid committing real target lists, tokens, or sensitive findings.
