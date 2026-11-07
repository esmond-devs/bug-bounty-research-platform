# Bug Bounty Security Research Platform

**Scope-first authorized reconnaissance and educational security research — Python CLI + local dashboard MVP (v0.2).**

This repository contains an early prototype, not yet a production-ready bug bounty automation service. It validates user-provided target hostnames against explicit include/exclude policies and optionally performs approved, low-impact HTTPS HEAD checks. Results are saved as JSON, with explanations for missing HTTP security headers.

## Local interactive dashboard

```bash
python dashboard.py --policy examples/policy.json
```

Open http://127.0.0.1:8765. Enter an authorized root domain and select **Discover CT records**. The dashboard queries the public certificate-transparency index (crt.sh) and displays in-scope and excluded candidate names. It does **not** contact discovered hosts, run active checks, or persist findings between restarts. CT queries send the root domain to a third-party service; confirm this is permitted by your program.

## Stronger active-check requirements

Active checks now additionally require `authorized_ip_cidrs` in policy rules, containing explicitly approved **public** destination networks. Example: `"authorized_ip_cidrs": ["203.0.113.0/24"]` is documentation-only (reserved IPs will be rejected). Do not use a broad cloud provider range merely because a hostname resolves into it. Without approved networks, active checks fail closed. This does not replace full CNAME-chain and infrastructure ownership verification.

## Requirements
Python 3.10+; curl (for optional HTTPS checks).

## Quick start
```bash
python -m unittest discover -s tests -v
python cli.py --policy examples/policy.json --targets examples/targets.txt --output results.json
```

This default run **does not send network requests**. Review the output and scope decisions before doing any active work.

To enable an authorized HTTPS check, edit a copy of the policy to set `active_http` and `researcher_approved` to `true`, after independently verifying the program permits automation and the specific target. Then add `--active` to the CLI. The checker only sends HTTPS HEAD to the root path, pins the resolved public IP, verifies TLS, and does not follow redirects. A scoped hostname is **not** sufficient proof of permission to probe third-party infrastructure.

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
Additional passive discovery sources, CNAME/third-party ownership checks, robust DNS rebinding defenses, distributed quotas, durable audit logs, UI, API, database, LLM recommendation engine, and advanced tool orchestration.

**Do not use this prototype against targets without explicit authorization.** Missing headers are not confirmed vulnerabilities. Avoid committing real target lists, tokens, or sensitive findings.
