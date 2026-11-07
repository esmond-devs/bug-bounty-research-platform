# Bug Bounty Security Research Platform

**Scope-first authorized reconnaissance and educational security research — Python CLI MVP.**

This repository contains an early prototype, not yet a production-ready bug bounty automation service. It validates user-provided target hostnames against explicit include/exclude policies and optionally performs approved, low-impact HTTPS HEAD checks. Results are saved as JSON, with explanations for missing HTTP security headers.

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
- JSON scope decisions and optional HTTPS response metadata
- Conservative active-mode approval flags and sequential request pacing
- Evidence-based educational security-header recommendations

## Not yet implemented
Autonomous subdomain enumeration, CNAME/third-party ownership checks, robust DNS rebinding defenses, distributed quotas, durable audit logs, UI, API, database, LLM recommendation engine, and advanced tool orchestration.

**Do not use this prototype against targets without explicit authorization.** Missing headers are not confirmed vulnerabilities. Avoid committing real target lists, tokens, or sensitive findings.
