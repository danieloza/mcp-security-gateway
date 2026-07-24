# Threat Model

## Scope

This model covers the portfolio runtime from the inbound MCP or operator API
request through policy evaluation, approval, controlled execution, and evidence
persistence.

It does not cover a corporate identity provider, arbitrary third-party MCP
servers, managed databases, production networks, or downstream business APIs.

## Assets

- workload and tenant identity;
- tool manifests and trust status;
- policy versions and decisions;
- approval decisions and capability leases;
- redacted request and execution evidence;
- audit-chain key and digests;
- Redis rate-limit state;
- local SQLite history.

## Trust Assumptions

- MCP clients, arguments, tool descriptions, annotations, and tool results are
  untrusted;
- the local manifest registry and policy code are authoritative;
- public demo credentials have no value outside the local portfolio runtime;
- the controlled execution adapter has no shell, arbitrary filesystem, or
  network access;
- deployment infrastructure must protect environment variables and persistent
  volumes.

## Threats and Controls

| Threat | Control | Residual risk |
| --- | --- | --- |
| Credential database disclosure | Store SHA-256 API-key digests only; migrate legacy plaintext rows | Real deployments should use short-lived workload identity rather than static keys |
| Credential disclosure through Redis | Rate-limit on an opaque actor digest | Redis operators still observe traffic volume |
| Cross-tenant object access | Bind all request, approval, incident, tool, and evidence lookups to organization | Corporate tenant provisioning is outside the portfolio runtime |
| Predictable identifiers | Cryptographically random resource IDs | IDs are still visible to authorized callers |
| Tool-description or schema rug pull | Pin canonical manifest digest; detect field changes; quarantine | Registry administrators remain privileged |
| Untrusted tool annotations | Treat annotations as hints; use local policy and risk metadata as authority | Incorrect local risk classification still requires review |
| Approval payload substitution | Bind approval and lease to the exact request and argument digests | SHA-256 collision risk is considered negligible |
| Approval replay | Random, short-lived lease; digest-only storage; atomic one-time consumption | Stolen unexpired lease can be used by the bound workload |
| Maker self-approval | Reject approval when checker equals request maker | Organizational group governance is not modeled |
| Secret exfiltration in arguments | Recursive secret-key/value detection, redaction, and hard block | Pattern detection cannot replace enterprise DLP |
| SSRF to internal or metadata endpoints | No arbitrary outbound connector; flag loopback/private/link-local literal destinations | Future connector DNS resolution requires rebinding-safe egress enforcement |
| MCP DNS rebinding | Validate browser Origin against an allowlist | Non-browser clients authenticate with Bearer credentials |
| Header/body policy split | Reject mismatched `Mcp-Method` and `Mcp-Name` values | Upstream infrastructure must preserve the validated headers |
| Request flooding | Bounded request size and Redis-backed caller rate limit | Edge-level connection and bandwidth controls remain necessary |
| Redis loss | Refuse in-memory fallback in production mode | Local mode intentionally falls back for portability |
| Audit record modification | HMAC-chained events and evidence verification | Local key and database share a runtime; external anchoring is not included |
| Host filesystem modification | Fixed adapter only stages sandbox metadata; no shell execution | A future real connector needs separate process isolation |

## Security Invariants

- no raw API key is persisted or returned;
- no MCP call executes before identity, manifest, schema, scope, DLP, rate, and
  environment checks;
- a high-risk call cannot execute without a fresh exact-payload lease;
- approval and execution are tenant-bound;
- manifest drift blocks execution once quarantined;
- production administration never reaches the local adapter;
- audit evidence contains redacted payloads and verifiable chain metadata.

## Production Requirements

A production design would additionally require:

- OAuth 2.1 resource-server validation and audience-bound short-lived tokens;
- managed secrets and cryptographic key rotation;
- PostgreSQL with migrations, backup, point-in-time recovery, and least-privilege
  roles;
- managed Redis with high availability;
- an allowlisted upstream connector with DNS resolution checks, egress firewall,
  TLS validation, timeouts, and redirect controls;
- signed server onboarding and manifest releases;
- sandboxed connector processes or containers;
- centralized logs, metrics, traces, paging, and incident ownership;
- immutable evidence archival and retention policy;
- load, concurrency, replay, and disaster-recovery testing.
