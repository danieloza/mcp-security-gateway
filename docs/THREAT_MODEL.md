# Threat Model

## Scope

This model covers the portfolio runtime from the inbound MCP or operator API
request through authentication, policy evaluation, approval, execution by the
built-in adapter or a configured upstream MCP server, and evidence persistence.

It does not cover the authorization server itself, a corporate identity
provider, the internals of upstream MCP servers, managed databases, production
networks, or downstream business APIs.

## Assets

- workload and tenant identity;
- tool manifests and trust status, including upstream tool pins;
- the OAuth resource identity (audience) and the subject map;
- policy versions and decisions;
- approval decisions and capability leases;
- redacted request and execution evidence;
- audit-chain key and digests;
- Redis rate-limit state;
- local SQLite history.

## Trust Assumptions

- MCP clients, arguments, tool descriptions, annotations, and tool results are
  untrusted;
- upstream MCP servers are untrusted. Their tool definitions can change at any
  time, and their output can carry instructions aimed at the agent;
- in OAuth mode, the configured authorization server and its JWKS endpoint are
  trusted to issue tokens;
- the local manifest registry and policy code are authoritative;
- public demo credentials have no value outside the local portfolio runtime;
- the controlled execution adapter has no shell, arbitrary filesystem, or
  network access;
- the upstream client reaches only operator-configured URLs;
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
| Approval replay | Random, short-lived lease; digest-only storage; atomic one-time claim and consumption | Stolen unexpired lease can be used by the bound workload |
| Maker self-approval | Reject approval when checker equals request maker | Organizational group governance is not modeled |
| Privileged lease hijack | Approval returns no credential; only the maker can claim and execute a lease; platform administrators have no execution override | Database administrators remain privileged |
| Theatrical security tests | Attack Lab replays each attack through the real gateway flow on an isolated replica; tests prove it fails when DLP or execution binding is disabled | The replica shares code, not live data, so tenant-specific drift is out of scope |
| Secret exfiltration in arguments | Recursive secret-key/value detection, redaction, and hard block | Pattern detection cannot replace enterprise DLP |
| SSRF to internal or metadata endpoints | No agent-controlled outbound connector; upstream URLs come only from operator configuration; flag non-global literal destinations, including decimal, hex, octal, and shortened IPv4 forms; fail closed on malformed numeric hosts | Future connector DNS resolution requires rebinding-safe egress enforcement |
| MCP DNS rebinding | Validate browser Origin against an allowlist | Non-browser clients authenticate with Bearer credentials |
| Header/body policy split | Reject mismatched `Mcp-Method` and `Mcp-Name` values | Upstream infrastructure must preserve the validated headers |
| Request flooding | Bounded request size and Redis-backed caller rate limit | Edge-level connection and bandwidth controls remain necessary |
| Redis loss | Refuse in-memory fallback in production mode | Local mode intentionally falls back for portability |
| Audit record modification | HMAC-chained events and evidence verification | Local key and database share a runtime; external anchoring is not included |
| Host filesystem modification | Fixed adapter only stages sandbox metadata; no shell execution; traversal, drive, stream, and non-allowlisted paths are rejected by policy before approval and again by the adapter | A future real connector needs separate process isolation |
| Silent execution failure | Adapter failures are persisted as failed executions and HMAC-chained `tool_execution_failed` events | Failure reasons are redacted by pattern, not by a full DLP engine |
| Tool poisoning: hidden instructions in a new upstream tool's definition | Pattern scan at sync; quarantine on first sight; quarantined tools are not listed to agents | Patterns, not a proof: a novel phrasing can pass review |
| Upstream rug pull after review | Compare the served definition with the pin on every call and again just before forwarding; on a change, quarantine, deny and open an incident, also between approval and execution | Definitions are compared, not behavior: an upstream can still act differently from what it declares |
| Prompt injection through tool output | Inspect upstream output before it reaches the agent; withhold it with finding types, a digest, an incident and an audit event; mark the request `output_withheld` | Patterns, not a proof: no match only means no known pattern was found |
| Token passthrough to an upstream | The upstream client has no access to the caller's credentials and sends only protocol headers | Upstream credentials are not supported yet |
| Hostile upstream answers | No redirects, a 1 MiB cap, a 10 s timeout; an unreachable upstream fails closed | No egress policy or rebinding-safe DNS for upstream hosts |
| Token minted for another resource | `aud` must contain the gateway's resource URI (RFC 8707) | Depends on the authorization server setting the audience |
| Algorithm confusion (`none`, HS256 with the public key) | Asymmetric allowlist, checked before any key lookup and again when decoding | Signature checks rely on PyJWT and `cryptography` |
| Unknown or unmapped token subject | Explicit subject map; unknown subjects are refused, never created | The map is maintained by hand |
| Public demo keys in production | Production mode refuses to start unless OAuth mode is on | The guard keys off `MSG_ENVIRONMENT=production`: a shared or staging deployment left on the default `local` still accepts the public keys |

## Security Invariants

- no raw API key is persisted or returned;
- no MCP call executes before identity, manifest, schema, scope, DLP, rate, and
  environment checks;
- a high-risk call cannot execute without a fresh exact-payload lease;
- only the requesting workload can claim or execute a lease, and approvers
  never hold it;
- approval and execution are tenant-bound;
- manifest drift blocks execution once quarantined;
- production administration never reaches the local adapter;
- audit evidence contains redacted payloads and verifiable chain metadata;
- an upstream tool is forwarded only while its served definition matches its
  pin;
- a quarantined tool is never listed to an agent;
- the caller's credential never leaves the gateway;
- upstream output that matches an injection pattern never reaches the agent;
- production never accepts the public demo keys.

## Production Requirements

A production design would additionally require:

- a corporate identity provider behind OAuth mode, with interactive clients
  on the authorization code flow with PKCE, and short token lifetimes;
- managed secrets and cryptographic key rotation;
- PostgreSQL with migrations, backup, point-in-time recovery, and least-privilege
  roles;
- managed Redis with high availability;
- egress policy and rebinding-safe DNS resolution for upstream hosts, TLS
  validation, and upstream credentials from a secret store (the current client
  already refuses redirects and caps size and time);
- signed server onboarding and manifest releases;
- sandboxed connector processes or containers;
- centralized logs, metrics, traces, paging, and incident ownership;
- immutable evidence archival and retention policy;
- load, concurrency, replay, and disaster-recovery testing.
