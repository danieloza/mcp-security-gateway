# MCP Security Gateway

> Protocol-aware runtime firewall for verified MCP tool execution.

[![CI](https://github.com/danieloza/mcp-security-gateway/actions/workflows/ci.yml/badge.svg)](https://github.com/danieloza/mcp-security-gateway/actions/workflows/ci.yml)
[![Release](https://img.shields.io/badge/Release-v0.3.0-22C55E?style=for-the-badge)](https://github.com/danieloza/mcp-security-gateway/releases/tag/v0.3.0)
![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-Runtime_Gateway-009688?style=for-the-badge&logo=fastapi&logoColor=white)
![MCP](https://img.shields.io/badge/MCP-tools%2Fcall-111827?style=for-the-badge)
![Security Tests](https://img.shields.io/badge/Security_Tests-62_Passing-16A34A?style=for-the-badge)
![API Keys](https://img.shields.io/badge/API_Keys-Digest_Only-0284C7?style=for-the-badge)
[![License: MIT](https://img.shields.io/badge/License-MIT-F59E0B?style=for-the-badge)](LICENSE)

[Overview](#what-it-solves) · [Product Demo](#product-demo) · [Product Tour](#product-tour) · [Verified Execution](#verified-execution-flow) · [Connect a Client](#connect-your-client) · [API](docs/API_EXAMPLES.md) · [Threat Model](docs/THREAT_MODEL.md) · [Patch Notes](CHANGELOG.md) · [MIT License](LICENSE)

![MCP Security Gateway module launcher with live status for each module](docs/assets/gateway-dashboard.png)

## What It Solves

Agents can discover powerful MCP tools, but discovery is not authorization. A
production control point must determine:

- which workload and tenant initiated the call;
- whether the server, tool description, and JSON schema still match an approved
  manifest;
- whether the requested scope and arguments fit policy;
- whether secrets or forbidden destinations appear in the call;
- whether a human must approve the exact payload;
- whether the approved call was modified, replayed, or executed twice;
- what evidence proves the final outcome.

MCP Security Gateway places that control point between an MCP client and a fixed
tool execution adapter. It supports protocol-level `initialize`, `ping`,
`tools/list`, and `tools/call`, then applies deterministic controls before any
side effect.

## Product Demo

This walkthrough is generated from the running gateway, not from mocked
screens. It follows one governed request across policy evaluation,
maker-checker approval, adversarial security tests, execution, and evidence.

![MCP Security Gateway verified execution demo](docs/assets/mcp-security-gateway-demo.gif)

| Stage | Control | Observable proof |
| --- | --- | --- |
| Request | Scope, environment, DLP, rate, and adapter policy | `executed`, `awaiting approval`, or `blocked` before side effects, with the reason and per-control trace |
| Approval | Maker-checker separation | Tool, justification, redacted payload, and digest shown to the checker |
| Attack testing | MCP abuse cases replayed through the gateway | Rug pull, tampering, secret egress, encoded SSRF, and key-storage checks |
| Execution | One-time capability lease claimed by the maker | Caller, manifest, arguments, policy, and expiry re-verified |
| Evidence | HMAC-linked audit events | Policy, approval, lease claim, and execution chain with integrity status |

The operator-led version takes about 90 seconds. See the
[presenter script](docs/DEMO_GUIDE.md) for the exact credential switches and
talk track.

## Verified Execution Flow

```mermaid
flowchart LR
  Client["Agent / MCP client"] --> Transport["Streamable-style HTTP /mcp"]
  Transport --> Identity["Workload identity"]
  Identity --> Manifest["Pinned tool manifest"]
  Manifest --> Policy["Scope + DLP + rate + environment policy"]
  Policy -->|low risk| Execute["Controlled execution adapter"]
  Policy -->|high risk| Approval["Maker-checker approval"]
  Approval --> Lease["One-time capability lease"]
  Lease --> Execute
  Policy -->|deny| Incident["Incident"]
  Execute --> Evidence["HMAC-chained evidence"]
```

Every governed request records:

- random, non-enumerable identifiers;
- tenant, workload, server, tool, scope, and policy version;
- SHA-256 argument, manifest, and governed-request digests;
- a redacted argument representation;
- the policy trace and decision reason;
- approval actor, lease expiry, execution result digest, and audit-chain events.

## Security Capabilities

### API key hygiene

- raw credentials are accepted only at the request boundary;
- SQLite stores SHA-256 digests, never recoverable API-key values;
- legacy plaintext demo rows are migrated to digest-only storage;
- API responses never expose credential material;
- Redis rate-limit keys use an opaque subject digest rather than the credential;
- production mode refuses an in-memory rate-limit fallback.

The values in [Demo credentials](#demo-credentials) are intentionally public
portfolio credentials, not secrets. They exist only to make the local walkthrough
repeatable.

### Tool Manifest Trust

Tool names, descriptions, JSON schemas, required scopes, risk levels, and
annotations are fingerprinted. Candidate changes produce a field-level diff.
Security administrators can quarantine a drifted tool; a platform administrator
must explicitly restore its trust state.

MCP tool annotations are retained for interoperability and operator context, but
the gateway does not treat server-provided hints as authorization.

### Approval-bound capability leases

High-risk calls are held before execution. Approval itself hands out no
credential: the checker authorizes, and only the requesting workload can then
claim a random, short-lived, one-use lease bound to:

- tenant and requesting workload;
- server, tool, scope, and policy version;
- approved manifest digest;
- exact argument digest;
- complete governed-request digest.

Changing the path, payload, tool schema, caller, or policy context invalidates
execution. Reusing or re-claiming the lease is rejected. Neither the checker nor
a platform administrator can claim or execute another workload's lease.

### MCP Attack Lab

The operator console replays each attack through the real gateway flow —
submission, policy, approval, lease claim, and execution — on an isolated,
freshly seeded replica, so the live tenant's traffic and incidents stay
untouched:

- tool-description rug pull followed by a call to the drifted tool;
- argument substitution after approval and lease claim;
- secret-bearing tool arguments;
- a decimal-encoded cloud-metadata SSRF destination;
- plaintext API-key persistence (checked against the live schema).

A probe that crashes is reported as a failed control, and the test suite proves
the lab fails when argument DLP or execution binding is disabled.

## Operator Console

The dashboard opens on a module launcher: one tile per module, each with a live
status such as pending approvals or the last Attack Lab score. A tile opens that
module on its own screen; **All modules**, `Esc`, or the browser Back button
returns to the launcher, and each module has a direct link such as
`/dashboard#traffic`. The credential field stays in the top bar so roles can be
switched from any module.

The modules provide:

- live MCP policy and execution traffic, with the decision reason on every row
  and an expandable trace of each policy control;
- tool trust registry with manifest fingerprints;
- maker-checker approval workbench that shows the tool, justification, and
  redacted payload being approved;
- maker-only lease claim and execution without browser persistence;
- attack-lab results;
- request evidence timeline and chain-integrity status;
- a four-call guided defense sequence for portfolio presentations.

The UI keeps the entered credential only in JavaScript memory. It does not use
cookies or browser storage. Tool arguments and justifications are
attacker-controlled, so the console renders them as text only; a test guards the
shipped script against HTML sinks such as `innerHTML`.

## Product Tour

The screenshots below use a clean local database and the same API paths covered
by the automated tests.

### 1. Policy enforcement before execution

![Policy decisions with an expanded control trace](docs/assets/policy-enforcement.png)

One table separates policy decision from execution state. Safe knowledge access
executes, a regulated write pauses, and forbidden production or secret-bearing
calls are contained. Every row states its reason; the expanded trace shows
argument DLP failing on a secret while the stored arguments stay redacted.

### 2. Maker-checker approval bound to the payload

![Maker-checker exact payload approval](docs/assets/approval-workbench.png)

The reviewer sees the tool, justification, redacted payload, payload digest,
maker, and checker. Approval lets only the maker claim a short-lived capability
lease for that immutable payload.

### 3. Adversarial controls as executable evidence

![MCP Attack Lab showing five verified controls](docs/assets/attack-lab.png)

The Attack Lab replays manifest rug pulls, post-approval argument tampering,
secret exfiltration, and a decimal-encoded cloud-metadata SSRF destination
through the real gateway flow on an isolated replica, and checks digest-only
API-key storage. Each card shows the gateway's own rejection.

### 4. Tamper-evident evidence chain

![Verified policy, approval, lease, and execution evidence chain](docs/assets/evidence-chain.png)

The evidence explorer links the policy decision, the checker's approval, the
maker's lease claim, and the execution, and verifies the organization audit
chain before presenting the evidence-pack digest.

## API Surface

### MCP protocol boundary

- `POST /mcp` — `initialize`, `ping`, `tools/list`, `tools/call`, and
  `notifications/*` (see [Connect Your Client](#connect-your-client))

### Operator API

- `GET /health`
- `GET /me`
- `GET /mcp-servers`
- `GET /policies`
- `GET /tool-registry`
- `POST /tool-registry/{tool_id}/verify`
- `POST /tool-registry/{tool_id}/restore`
- `GET /requests`
- `GET /requests/{request_id}`
- `POST /requests`
- `GET /approvals`
- `POST /approvals/{approval_id}/decision`
- `POST /requests/{request_id}/lease`
- `POST /requests/{request_id}/execute`
- `GET /requests/{request_id}/evidence`
- `GET /incidents`
- `POST /attack-lab/run`

See [API examples](docs/API_EXAMPLES.md) for protocol and approval flows.

## Run Locally

```powershell
git clone https://github.com/danieloza/mcp-security-gateway.git
cd mcp-security-gateway

python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
python -m uvicorn mcp_security_gateway.main:app --reload --host 127.0.0.1 --port 8000
```

Open:

- operator console: `http://127.0.0.1:8000/dashboard`
- local API documentation: `http://127.0.0.1:8000/docs`

Interactive API documentation is disabled automatically when
`MSG_ENVIRONMENT=production`.

## Demo Credentials

These credentials are public, local-only portfolio fixtures:

```text
operator:       msg-ops-demo
security admin: msg-security-demo
platform admin: msg-platform-demo
```

Use the preferred header:

```http
Authorization: Bearer msg-ops-demo
```

`X-API-Key` remains available for backward-compatible local examples, but new
integrations should use the Bearer transport. Real deployments must replace
these fixtures with workload identity or an organizational authorization
service.

## Connect Your Client

Point any MCP client that supports the Streamable HTTP transport and custom
headers at `http://127.0.0.1:8000/mcp` with a Bearer credential. The agent then
sees every governance decision as a normal tool result:

| Gateway decision | `structuredContent.status` | `isError` |
| --- | --- | --- |
| verified low-risk call | `executed` | `false` |
| high-risk call held for maker-checker | `approval_required` | `false` |
| policy violation (secret, scope, traversal, production admin) | `denied` | `true` |

### Claude Code

```bash
claude mcp add --transport http mcp-security-gateway http://127.0.0.1:8000/mcp \
  --header "Authorization: Bearer msg-ops-demo"
```

### Cursor (`.cursor/mcp.json`)

```json
{
  "mcpServers": {
    "mcp-security-gateway": {
      "url": "http://127.0.0.1:8000/mcp",
      "headers": { "Authorization": "Bearer msg-ops-demo" }
    }
  }
}
```

### VS Code (`.vscode/mcp.json`)

```json
{
  "servers": {
    "mcp-security-gateway": {
      "type": "http",
      "url": "http://127.0.0.1:8000/mcp",
      "headers": { "Authorization": "Bearer msg-ops-demo" }
    }
  }
}
```

### MCP Python SDK

```python
import asyncio

from mcp import ClientSession
from mcp.client.streamable_http import create_mcp_http_client, streamable_http_client


async def main() -> None:
    http = create_mcp_http_client(headers={"Authorization": "Bearer msg-ops-demo"})
    async with http, streamable_http_client("http://127.0.0.1:8000/mcp", http_client=http) as streams:
        async with ClientSession(streams[0], streams[1]) as session:
            await session.initialize()
            result = await session.call_tool("kb.search", {"query": "manifest quarantine"})
            print(result.structured_content["status"])


asyncio.run(main())
```

### Protocol contract

- negotiates MCP `2025-11-25` or `2025-06-18`; a client offering any other
  revision is answered with `2025-11-25`, the latest supported one;
- `2025-03-26` is not offered because it requires JSON-RPC batch support;
- notifications such as `notifications/initialized` return `202 Accepted`
  with no body;
- requests without an `id`, or with a `null` id, are rejected with `400`;
- an `MCP-Protocol-Version` header, when sent, must name a supported revision;
- capabilities advertise `tools.listChanged: false`, because there is no
  server-to-client stream (`GET /mcp` returns `405`).

Verification boundary, as run on 2026-11-17 against a local gateway on a fresh
database:

| Client | What was run | Result |
| --- | --- | --- |
| MCP Python SDK 2.3.0 | the snippet above, extended to one call per decision | negotiated `2025-11-25`; `tools/list` returned the three tools; `kb.search` → `executed`, `repo.write_file` → `approval_required`, `repo.write_file` with a secret → `denied` (`isError: true`); `ping` answered |
| Claude Code 2.1.248 | the `claude mcp add` command above, then `claude mcp list` | `✔ Connected` |
| Cursor, VS Code | not run | the snippets follow each client's documented remote HTTP format |

The Claude Code handshake, as observed on the wire:

1. a `server/discover` probe for revision `2026-07-28` is refused with
   `400 Bad Request`, because that revision is not supported;
2. Claude Code falls back to `initialize` and negotiates `2025-11-25`;
3. `notifications/initialized` returns `202`, the optional `GET /mcp` stream
   returns `405`, and `tools/list` returns the three tools.

A test pins the refusal of the probe and the fallback. A model calling tools
through Claude Code was not exercised.

By default, authentication is the static Bearer credential above. For OAuth,
see the next section.

## OAuth Resource-Server Mode

With `MSG_AUTH_MODE=oauth`, the gateway is an OAuth 2.1 resource server as the
MCP 2025-11-25 authorization specification describes it:

- **It validates tokens. It does not issue them.** The tokens come from an
  external authorization server.
- **It publishes RFC 9728 protected-resource metadata** at
  `/.well-known/oauth-protected-resource/mcp`. This is the path-inserted URI
  for a resource at `<origin>/mcp`.
- **A missing or invalid token is a `401`.** The response carries
  `WWW-Authenticate: Bearer` with `resource_metadata` and `scope`, and
  `error="invalid_token"` when a token was sent.
- **A token without the needed scope is a `403`** with
  `error="insufficient_scope"`. The scope is `mcp:tools` for `/mcp` and
  `gateway:console` for the operator API.
- **Tokens are checked against the authorization server's JWKS:**
  - the signature, with asymmetric algorithms only, so `none` and HS256 are
    refused;
  - `iss`, `exp`, `nbf` and `sub`;
  - **`aud`, which must contain the gateway's resource URI** (RFC 8707). A
    token minted for another resource is refused.
- **A token's `sub` must be mapped explicitly to a gateway user.** An unknown
  subject is refused, never created.
- **The token goes no further than authentication.** Tool execution sees only
  the mapped user, so a client's token is never passed through.
- **The static demo keys and `X-API-Key` are not accepted** in this mode.
- **Production refuses to start in static mode.**

| Variable | Example (local Keycloak realm) |
| --- | --- |
| `MSG_AUTH_MODE` | `oauth` |
| `MSG_OAUTH_RESOURCE` | `http://127.0.0.1:8000/mcp` |
| `MSG_OAUTH_ISSUER` | `http://127.0.0.1:8081/realms/gateway` |
| `MSG_OAUTH_JWKS_URL` | `http://127.0.0.1:8081/realms/gateway/protocol/openid-connect/certs` |
| `MSG_OAUTH_SUBJECTS` | `5f6c1d2e-0a41-4f43-9a0b-6e1d7c2a9b01=usr_ops,8a3e4b7c-2d19-4c55-b1e2-3f9a0d6c4e02=usr_security` |
| `MSG_OAUTH_ALGORITHMS` | optional, default `RS256,ES256` |

### Try it with a local Keycloak

```powershell
docker compose --profile oauth up keycloak
# in another shell, with the variables above set:
python -m uvicorn mcp_security_gateway.main:app --host 127.0.0.1 --port 8000

$token = (Invoke-RestMethod -Method Post `
  -Uri http://127.0.0.1:8081/realms/gateway/protocol/openid-connect/token `
  -Body @{ grant_type = "password"; client_id = "gateway-demo-cli";
           username = "ops"; password = "ops-demo"; scope = "mcp:tools" }).access_token
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/mcp `
  -Headers @{ Authorization = "Bearer $token" } -ContentType "application/json" `
  -Body '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

**About the realm** (`deploy/keycloak/gateway-realm.json`):
- its users have fixed ids, so the subject map above stays stable;
- each scope carries an audience mapper that puts the resource URI in `aud`;
- its users, passwords and the password grant are public, local-only fixtures for
  scripted tokens. Interactive MCP clients use the authorization code flow with
  PKCE.

**As run on 2026-11-17** against Keycloak 26.4.5 with this realm, on a fresh
database:
- the metadata document and the 401 challenge were as described above;
- an `ops` token with `mcp:tools` got `tools/list`, `kb.search` → `executed` and
  `repo.write_file` → `approval_required`;
- the same token on the console API got `403 insufficient_scope`;
- with `gateway:console` tokens, the maker could not approve their own request
  (`403`), and `security` could;
- the static demo key got `401 invalid_token`.

**Claude Code 2.1.248**, pointed at the gateway in this mode without a header,
read the 401 challenge, fetched the metadata, found the Keycloak realm and tried
dynamic client registration. The realm's "Trusted Hosts" policy refused it: the
realm only issues scripted tokens. An interactive login from an MCP client
needs an authorization server that accepts its registration.

**Not part of this mode:**
- the gateway as an authorization server;
- dynamic client registration;
- token exchange;
- a console login.

## Guided Demo

1. Open the operator console.
2. Connect as `msg-ops-demo` in the top bar.
3. Open the **Overview** tile and run **Guided defense**:
   - `kb.search` is verified and executed;
   - `repo.write_file` is held for approval;
   - `ops.restart_service` is hard-blocked;
   - a Bearer-like value inside arguments is redacted and contained.
4. Switch to `msg-security-demo`.
5. In **Approvals**, approve the exact sandbox-write payload; then run the
   **Attack lab**.
6. Switch back to `msg-ops-demo`.
7. In **Live traffic**, select **Claim & execute**: only the maker can claim the
   one-time lease, and the console spends it immediately and opens **Evidence**.
8. In **Tool trust**, simulate a changed tool description and show the manifest
   drift result.

The full presenter script is in [docs/DEMO_GUIDE.md](docs/DEMO_GUIDE.md).

## Docker Compose

```powershell
docker compose config --quiet
docker compose up --build
```

Compose binds the API to loopback, keeps Redis on the internal network, drops
Linux capabilities, uses a non-root application user, and mounts only the
persistent SQLite data volume. The local fallback audit key remains a
development convenience; configure a managed secret for any non-local runtime.

## Testing

```powershell
python -m pip install -e ".[dev]"
python -m pytest -q
python -m pip_audit .
docker compose config --quiet
```

The suite covers key migration, credential response shaping, MCP version
negotiation, notification handling, a full client handshake,
verified low-risk execution, maker-checker separation, maker-only lease claims,
platform-admin execution separation, argument-bound leases, lease replay,
attack-lab replicas that fail when controls are disabled, manifest quarantine, DLP blocking, sandbox-path rejection before
approval, audited execution failures, encoded-IPv4 SSRF destinations, tenant
isolation, Origin validation, strict request schemas, evidence integrity,
single-source versioning, dashboard headers, and the absence of HTML sinks in
the dashboard script.

The OAuth tests (`tests/test_oauth.py`) sign tokens with keys generated during
the test run, so they need no authorization server. They cover:
- the metadata document and the `401` and `403` challenges;
- each refused token:
  - a wrong audience, or none;
  - expired, or not yet valid;
  - a wrong issuer;
  - a bad signature, or an unknown key;
  - `alg: none`, or HS256 with the public key as its secret;
  - no subject, or an unknown one;
  - a static key, or `X-API-Key`;
- a missing scope;
- maker-checker separation with OAuth identities;
- unavailable signing keys (`503`);
- the production guard, and unsafe settings.

## Production-shaped, Not Production-ready

This repository proves the security control path. It intentionally does not
claim to be a drop-in enterprise gateway.

Current portfolio boundaries:

- SQLite persistence rather than managed PostgreSQL and migrations;
- public local demo credentials by default. OAuth resource-server mode
  validates tokens from an external authorization server, but has been run only
  against a local Keycloak realm, not a corporate identity provider;
- a fixed in-process execution adapter rather than arbitrary remote MCP server
  registration;
- no unrestricted outbound HTTP, filesystem, shell, or production operations;
- local HMAC evidence integrity without external timestamping or immutable
  archival;
- single-node operator workflow without organizational incident ownership.

A company rollout would add its own identity provider behind OAuth mode, managed
secrets and key rotation, PostgreSQL, durable queues, network egress policy, a controlled
server onboarding process, signed manifest releases, centralized telemetry,
backups, incident response, and independent audit retention.

See [Threat Model](docs/THREAT_MODEL.md) and
[Architecture](docs/ARCHITECTURE.md).

## Proof Assets

- animated product demo: [docs/assets/mcp-security-gateway-demo.gif](docs/assets/mcp-security-gateway-demo.gif)
- module launcher: [docs/assets/gateway-dashboard.png](docs/assets/gateway-dashboard.png)
- policy enforcement: [docs/assets/policy-enforcement.png](docs/assets/policy-enforcement.png)
- maker-checker approval: [docs/assets/approval-workbench.png](docs/assets/approval-workbench.png)
- Attack Lab: [docs/assets/attack-lab.png](docs/assets/attack-lab.png)
- evidence chain: [docs/assets/evidence-chain.png](docs/assets/evidence-chain.png)
- architecture: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
- threat model: [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)
- API examples: [docs/API_EXAMPLES.md](docs/API_EXAMPLES.md)
- guided demo: [docs/DEMO_GUIDE.md](docs/DEMO_GUIDE.md)
- case study: [docs/CASE_STUDY.md](docs/CASE_STUDY.md)
- patch notes: [CHANGELOG.md](CHANGELOG.md)

## Related Project

[Regulated AI Agent Platform](https://github.com/danieloza/regulated-ai-agent-platform)
demonstrates broader governance lifecycles. MCP Security Gateway stays deliberately
narrow: it is the protocol-specific enforcement boundary for agent tool traffic.

## License

Copyright © 2026 Daniel Danek. Released under the
[MIT License](LICENSE).
