# Patch Notes

Significant changes to the MCP Security Gateway are documented here.

## [Unreleased]

### Security fixes

- reject unsafe `repo.write_file` paths (traversal, absolute, drive, NTFS
  stream, non-allowlisted type) during policy evaluation, before approval and
  lease issuance; the adapter repeats the same check before execution;
- record adapter failures as `failed` executions with an HMAC-chained
  `tool_execution_failed` event instead of leaving the request in
  `lease_issued` with no evidence;
- flag decimal, hex, octal, and shortened IPv4 literals (for example
  `http://2130706433/`) and other non-global addresses such as
  `100.100.100.200` as forbidden destinations; malformed numeric hosts fail
  closed;
- read the package, API, and MCP `serverInfo` version from a single
  `__version__` source.

### MCP protocol compliance

- negotiate the protocol version: echo `2025-11-25` or `2025-06-18` when the
  client offers it, otherwise answer with `2025-11-25`; `2025-03-26` is not
  offered because it requires JSON-RPC batch support;
- acknowledge notifications such as `notifications/initialized` with
  `202 Accepted` and no body instead of a JSON-RPC error;
- reject requests without an `id` or with a `null` id, and an unsupported
  `MCP-Protocol-Version` header, with `400`;
- advertise `tools.listChanged: false`, because the gateway has no
  server-to-client stream;
- added a "Connect Your Client" README section for Claude Code, Cursor,
  VS Code, and the MCP Python SDK; the official SDK 2.3.0 client completed a
  full governed session against the gateway.

### Testing

- expanded the test suite from 20 to 54 tests.

## [0.2.1] - 2026-07-24

### Commercial project showcase

- added a compact animated product walkthrough generated from the running
  gateway;
- added full-resolution views for policy enforcement, maker-checker approval,
  the MCP Attack Lab, and the tamper-evident evidence chain;
- restructured the README as an executive product tour while keeping technical
  boundaries and deployment limitations explicit;
- added release and MIT license badges plus package ownership metadata;
- released the repository under the MIT License.

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
