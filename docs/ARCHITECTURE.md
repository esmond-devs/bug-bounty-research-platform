# Architecture

Researcher-provided targets and program policy → scope gate → optional approved HTTPS HEAD probe → JSON evidence → recommendations.

Current implementation is a Python CLI. Planned components: passive discovery adapters, DNS/CNAME infrastructure authorization, immutable policy snapshots, shared quotas, evidence database, auditable approvals, FastAPI, and Next.js. LLMs may explain approved recommendations but must never execute arbitrary commands or override policy.
