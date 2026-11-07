# Security Model

For authorized bug bounty research only. Verify that the program permits the specific activity, automation, and target.

Implemented baseline: deny-by-default hostname scope, exclusions, active approval flags, TLS verification, no redirects, public IP validation and pinned destinations.

Production gaps: CNAME/third-party ownership validation, network egress isolation, DNS rebinding defenses, signed approval, shared rate limits, audit trails, emergency stop, secrets management, and comprehensive integration testing. Never publish sensitive findings or credentials.
