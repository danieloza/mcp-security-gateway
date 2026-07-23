# Patch Notes

Significant changes to the MCP Security Gateway are documented here.

## [0.2.0] - 2026-07-24

### Verified MCP execution

- added a protocol-aware `/mcp` boundary for `initialize`, `ping`, `tools/list`,
  and `tools/call`;
- added a fixed controlled adapter for low-risk knowledge reads and isolated
  sandbox-write evidence;
- added strict `Mcp-Method` and `Mcp-Name` header/body consistency checks;
- added Origin allowlisting for browser MCP connections.

### Credential and identity hardening

- replaced plaintext API-key persistence with SHA-256 digest-only storage;
- added automatic migration for legacy plaintext demo rows;
- removed credential material from models and API responses;
- replaced raw Redis credential keys with opaque actor digests;
- added preferred Bearer authentication while retaining the legacy local header;
- added tenant-bound tool, policy, request, approval, incident, execution, and
  evidence access.

### Approval integrity

- replaced sequential identifiers with cryptographically random IDs;
- added argument, manifest, request, result, and evidence digests;
- added policy versions and control traces;
- added maker-checker self-approval protection;
- added short-lived one-time capability leases stored only as hashes;
- added exact-argument verification, atomic lease consumption, expiry, replay
  rejection, and duplicate-decision rejection.

### Tool trust and attack testing

- added canonical tool manifest fingerprints;
- added field-level description, schema, and annotation drift detection;
- added quarantine and platform-admin restoration controls;
- added deterministic tests for manifest rug pulls, approval tampering, secret
  exfiltration, metadata SSRF, and plaintext key persistence.

### Evidence and operator experience

- added HMAC-chained audit events and request evidence packs;
- added execution result recording with redaction, latency, and integrity
  digests;
- replaced the static project panel with an interactive responsive operator
  console;
- added guided presentation flow, live traffic, tool registry, approval
  workbench, Attack Lab, and Evidence Explorer.

### Runtime and delivery

- added strict request schemas, request-size checks, Trusted Host validation,
  CSP, clickjacking, MIME, referrer, and permissions headers;
- disabled API docs automatically in production mode;
- made Redis mandatory in production mode;
- hardened the container and Compose runtime with a non-root user, dropped
  capabilities, no-new-privileges, loopback binding, and an internal Redis
  service;
- expanded CI with commit-pinned actions and Python dependency auditing;
- expanded the test suite from 6 to 20 security and protocol tests.

## [0.1.0] - 2026-03-25

- introduced deterministic allow, approval, and block decisions;
- added SQLite request history, approvals, incidents, Redis-ready rate limits,
  secret redaction, FastAPI endpoints, tests, Docker Compose, and the first
  portfolio dashboard.
