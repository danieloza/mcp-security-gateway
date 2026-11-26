# Patch Notes

Significant changes to the MCP Security Gateway are documented here.

## [Unreleased]

### Tool names for function-calling models

- **`/mcp?tool_names=underscore` lists tools under aliases such as
  `kb_search`.** OpenAI and Azure OpenAI reject a function name with a dot, and
  n8n passes MCP names to the model unchanged. An n8n Cloud agent with an
  OpenAI model failed on its first request: `Invalid 'tools[0].function.name'`.
  Without the parameter, names are unchanged.
- **`tools/call` resolves the alias to the canonical name before any policy
  runs.** Manifests, approvals and the audit trail record only canonical names.
- **An alias that two tools would share goes to neither.** Both stay callable by
  their canonical names. A cached alias therefore never reaches a different tool
  after an upstream sync.
- **The mutation check has a fourth suite, `names`,** with six guards. The
  existing guard against listing quarantined tools follows the refactored line.

### Public sandbox

- **`MSG_ENVIRONMENT=sandbox`**, for a gateway that anyone may use. It keeps the
  public demo keys and adds the following limits:
  - a request limit per client address, read from the `X-Forwarded-For`
    entries that trusted proxies appended;
  - `411` for a request body without `Content-Length`;
  - a full reset on a schedule, on every start and when the database passes
    its size cap.

  Admins also get two controls: one makes the bundled test server swap a tool,
  the other resets the sandbox.
- **`GET /sandbox` shows callers their own address as the gateway sees it**,
  and how many `X-Forwarded-For` entries arrived. A private address there means
  `MSG_TRUSTED_PROXY_HOPS` is lower than the number of proxies in front.
- **`deploy/demo/Dockerfile`** runs the gateway and the poisoned example server
  in one container. **`render.yaml`** describes it as a free Render web service.
- **The Render service trusts three proxies.** The first deploy assumed one.
  `/sandbox` then showed three `X-Forwarded-For` entries on a request that sent
  none, and a private address as the caller's. With one hop, every visitor
  shared one rate-limit bucket. `MSG_TRUSTED_PROXY_HOPS` now accepts up to 5.
- **The console shows a sandbox strip** with the public keys and both controls.
- **CI builds, scans and smoke-tests the sandbox image**
  (`scripts/sandbox_smoke.py`). The mutation check has a third suite, with
  nine sandbox guards.

### Dependencies

- **Keycloak 26.4.5 → 26.8.2-2** in the compose profile `oauth` (#12). The
  realm imports without errors, and the OAuth walkthrough gives the same
  results.
- **`actions/setup-python` 7.0.0 → 7.1.0** in CI (#11).
- **Upper bounds raised to `redis<9` and `pytest<10`** (#13). CI passes with
  redis-py 8.1.0 and pytest 9.2.0, and the Docker smoke test runs the gateway
  against Redis with redis-py 8.1.0.

## [0.4.0] - 2026-11-18

### Breaking change

- **Production mode requires OAuth.** With `MSG_ENVIRONMENT=production`, the
  gateway refuses to start unless `MSG_AUTH_MODE=oauth`. Static mode accepts
  only the seeded demo keys, which are published in the README, so v0.3.0 in
  production mode accepted publicly known credentials. To upgrade a production
  deployment, configure an authorization server first (see
  [docs/OAUTH.md](docs/OAUTH.md)). Local and demo runs are unchanged:
  static mode stays the default.

### Proxy mode for upstream MCP servers

- **The gateway can sit in front of real MCP servers over Streamable HTTP.**
  Upstreams are configured in `MSG_UPSTREAMS`, a JSON list. Every upstream call
  follows the built-in control path, then is forwarded.
- **Pinning.** `POST /upstreams/{id}/sync`, or **Sync upstream** in the console,
  pins new tools under `<prefix>.<name>`. A new tool whose definition carries
  hidden instructions is quarantined on first sight.
- **Rug-pull detection.** The upstream definition is re-read on every call and
  again just before forwarding. A changed definition quarantines the tool and
  blocks the call, including between approval and execution. The console shows
  the pinned and served descriptions side by side, and decodes text hidden in
  Unicode tag characters.
- **Output inspection.** Tool output that looks like instructions to the agent
  is withheld (`response_blocked`, with the finding types and a digest). The
  checks are heuristics, and the README says so.
- **Withheld output is visible to operators.** Such a request has the
  execution status `output_withheld`, not `executed`, and **Live traffic**
  shows it in red.
- **Sync results are dated.** The console shows when the last sync ran. When a
  later call quarantines a tool, the row says so ("since then: quarantined").
- **Quarantined tools no longer appear in `tools/list`.**
- **A minimal upstream client** on `httpx`: no redirects, a 1 MiB cap, a
  timeout, JSON and SSE answers, and never the caller's credentials. An
  unreachable upstream fails closed.
- **`examples/poisoned_server.py`:** a deliberately malicious MCP server for
  demos and tests.

### OAuth resource-server mode

- **`MSG_AUTH_MODE=oauth`** turns the gateway into an OAuth 2.1 resource server,
  as MCP 2025-11-25 authorization describes it.
- **Metadata:** RFC 9728 protected-resource metadata at
  `/.well-known/oauth-protected-resource/mcp`.
- **Challenges:** `401` with `WWW-Authenticate: Bearer`, `resource_metadata` and
  `scope`, and `403` with `insufficient_scope`.
- **Token checks:** the signature against the authorization server's JWKS, with
  asymmetric algorithms only; then `iss`, `exp`, `nbf` and `sub`, and an `aud`
  that must contain the resource URI (RFC 8707).
- **Subjects:** each token subject is mapped explicitly to a gateway user. An
  unknown subject is refused.
- **Scopes:** `mcp:tools` for `/mcp`, and `gateway:console` for the operator
  API.
- **Unavailable signing keys** answer `503`, not `401`.
- **`/health`** reports the active `auth_mode`.
- **A local Keycloak realm**, in the compose profile `oauth`, issues scripted
  demo tokens.

### Client verification

- **The README's client instructions were run** against a local gateway on a
  fresh database. The MCP Python SDK 2.3.0 got all three decisions
  (`executed`, `approval_required`, `denied`). Claude Code 2.1.248 reported
  `✔ Connected` after a full handshake. Cursor and VS Code stay marked as not
  run.
- **The Claude Code handshake is documented.** Its `server/discover` probe for
  revision `2026-07-28` is refused with `400`, and it falls back to
  `initialize` at `2025-11-25`. A test pins the refusal and the fallback.

### Operator console

- **A module launcher replaces the sidebar.** There is one tile per module,
  following the dotted-card pattern with a corner icon on hover. Each tile shows
  a live status: requests and blocks, verified manifests, pending approvals, the
  last Attack Lab score, or the last evidence chain.
- **Each module opens on its own screen** with an **All modules** back button.
  `Esc`, browser Back and Forward, and direct links such as `#traffic` work.
- **The credential field is in the top bar,** so roles can be switched from any
  module. Focus moves to the module heading when a module opens.
- **A brand favicon** as a `data:` URI removes the `favicon.ico` 404 from the
  browser console.
- **Refreshed screenshots and demo GIF** from a clean demo database. The README
  hero is now the launcher with live status after the full walkthrough, and
  each module frame shows the All modules bar.

### Documentation

- **The README is shorter, and covers proxy and OAuth modes from the first
  section on:**
  - the overview;
  - the execution flow;
  - the API surface;
  - the client decision table, which now includes `response_blocked`;
  - a fifth Product Tour stop with a caught rug pull;
  - a short summary of each mode.
- **`docs/PROXY.md` and `docs/OAUTH.md`** hold the full reference for each
  mode, moved out of the README. Each has a diagram: the path of a proxied call,
  and the OAuth discovery and token checks.
- **`docs/assets/proxy-mode-demo.gif`** shows proxy mode in the console, step by
  step, and now opens the README.
- **The other documents in `docs/` cover both modes:**
  - the architecture;
  - the threat model, with tool poisoning, rug pulls, output injection, token
    passthrough and token audience;
  - the case study;
  - the API examples, with real gateway answers for a sync, a withheld output,
    a rug pull and the OAuth challenge;
  - the demo guide, with an optional act for the poisoned server.
- **The README's Docker section** says what the stack runs with, what CI checks,
  which findings have no fix yet, and that `docker compose down -v` deletes the
  database volume.

### Testing

- **123 tests, up from 61.** The new ones are:
  - 31 OAuth tests, with tokens signed by keys generated during the run;
  - 29 proxy tests;
  - a client-handshake test;
  - a test that every console tile opens exactly one module.
- **`scripts/mutation_check.py`** removes one guard at a time and checks that a
  test fails. It caught 11 of 11 mutations for proxy mode and 9 of 9 for OAuth
  mode. CI runs it on every pull request and on every push to `main`.
- **`scripts/e2e_proxy.py`** runs proxy mode end to end over real HTTP, with
  the MCP Python SDK as the agent: the poisoned example server and the gateway
  as separate processes, every step asserted. CI runs it too.
- **Both scripts write their results to the GitHub Actions run summary,** so a
  run page shows each mutation and each end-to-end step.
- **CI runs the tests and the dependency audit on Python 3.11 and 3.12.**
- **CI builds, scans and starts the Docker image** (the `docker` job):
  - Trivy fails the job on any HIGH or CRITICAL vulnerability that has a fix;
  - `scripts/docker_smoke.py` checks `/health` and one MCP call against the
    Compose stack.

### Dependencies

- **New runtime dependencies:**
  - `httpx`, for the upstream client;
  - `PyJWT[crypto]`, for token checks.
- **New optional extra `e2e`:** `mcp`, the MCP Python SDK, used by
  `scripts/e2e_proxy.py`.

### Packaging

- **The license is an SPDX expression** (`license = "MIT"` with
  `license-files`), and the license classifier is gone. setuptools had
  deprecated the old form, with builds to stop working from 2027-02-18. The
  build now requires setuptools 77 or later.
- **The Docker image ships the license file.** The Dockerfile did not copy
  `LICENSE`, so the installed package had no license text.
- **`docker compose up` starts again.** Redis runs as its own user. With all
  capabilities dropped, its image could no longer switch to that user from
  root, and the stack stopped at "dependency redis failed to start".
- **The image is patched and smaller.** Debian security updates are applied at
  build time, and pip, setuptools and wheel are removed after the install. The
  base image carried fixable HIGH findings in zlib and in setuptools and its
  vendored packages. Trivy now reports no HIGH or CRITICAL finding that has a
  fix. 47 HIGH findings remain in Debian packages for which Debian has no fix
  yet, and the README lists them.

### Maintenance

- **Dependabot proposes weekly updates** for pip, GitHub Actions, the base image
  and the Compose images. Each update waits 7 days after its release. Python
  minor versions and Compose major versions are left to a person.

## [0.3.0] - 2026-10-20

### Breaking change

- `POST /approvals/{approval_id}/decision` no longer returns
  `capability_lease` or `expires_at`. After approval the request is
  `lease_ready`, and the maker claims the one-time lease with
  `POST /requests/{request_id}/lease`, then executes as before. Integrations
  that read the lease from the approval response must switch to the claim call.

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

### Separation of duties and honest attack testing

- approval no longer returns a capability lease to the checker; the request
  becomes `lease_ready`, and only the maker can claim the lease once through
  `POST /requests/{request_id}/lease`, recorded as a `lease_claimed` event;
- removed the platform-administrator override that allowed executing another
  workload's approved request;
- the Attack Lab now replays rug pull, approval tampering, secret egress, and a
  decimal-encoded SSRF destination through the real gateway flow on an
  isolated, freshly seeded replica instead of comparing constants; crashing
  probes are reported as failed controls;
- the operator console replaces browser-held leases with a maker-only
  **Claim & execute** action.

### Operator console

- show the decision reason on every live-traffic row and an expandable trace of
  each policy control with its result and evidence;
- show the tool, justification, and redacted payload on approval cards, so the
  checker sees what "Approve exact payload" approves;
- render attacker-controlled arguments and justifications as text only; a
  browser probe with `<img onerror>`, `<script>`, and event-handler payloads
  injected no elements;
- keep request row actions on one line when a decision trace is expanded;
- refreshed the product screenshots and demo GIF from a clean demo database so
  they show decision traces, approval payloads, replayed attacks, and the lease
  claim.

### Testing

- expanded the test suite from 20 to 61 tests, including tests that prove the
  Attack Lab fails when argument DLP or execution binding is disabled and a
  guard against HTML sinks in the dashboard script.

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
