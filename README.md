# MCP Security Gateway

> Protocol-aware runtime firewall for verified MCP tool execution.

[![CI](https://github.com/danieloza/mcp-security-gateway/actions/workflows/ci.yml/badge.svg)](https://github.com/danieloza/mcp-security-gateway/actions/workflows/ci.yml)
[![Release](https://img.shields.io/badge/Release-v0.4.0-22C55E?style=for-the-badge)](https://github.com/danieloza/mcp-security-gateway/releases/tag/v0.4.0)
![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-Runtime_Gateway-009688?style=for-the-badge&logo=fastapi&logoColor=white)
![MCP](https://img.shields.io/badge/MCP-tools%2Fcall-111827?style=for-the-badge)
![Security Tests](https://img.shields.io/badge/Security_Tests-148_Passing-16A34A?style=for-the-badge)
![API Keys](https://img.shields.io/badge/API_Keys-Digest_Only-0284C7?style=for-the-badge)
[![License: MIT](https://img.shields.io/badge/License-MIT-F59E0B?style=for-the-badge)](LICENSE)

[Overview](#what-it-solves) · [Product Demo](#product-demo) · [Product Tour](#product-tour) · [Verified Execution](#verified-execution-flow) · [Connect a Client](#connect-your-client) · [Proxy Mode](#proxy-mode-real-mcp-servers-behind-the-gateway) · [OAuth](#oauth-resource-server-mode) · [API](docs/API_EXAMPLES.md) · [Threat Model](docs/THREAT_MODEL.md) · [Patch Notes](CHANGELOG.md) · [MIT License](LICENSE)

**[Try the live sandbox](https://mcp-security-gateway-sandbox.onrender.com/dashboard)** with the
public key `msg-security-demo`. Every visitor shares it, it resets every hour,
and the first load after a quiet spell takes about a minute while the free
instance wakes up. See [Public Sandbox](#public-sandbox).

![Proxy mode in the console: an upstream server synced, three agent calls, a rug pull blocked, and the diff with its hidden text decoded](docs/assets/proxy-mode-demo.gif)

*A deliberately malicious MCP server behind the gateway. Its tools are pinned
on review, its injected output never reaches the agent, and a description it
swaps after review is blocked on the next call. See
[Proxy Mode](#proxy-mode-real-mcp-servers-behind-the-gateway).*

## What It Solves

Agents can discover powerful MCP tools, but discovery is not authorization. A
production control point must determine:

- which workload and tenant initiated the call, and whether its token was
  issued for this gateway;
- whether the server, tool description, and JSON schema still match an approved
  manifest, at review time and at the moment of the call;
- whether the requested scope and arguments fit policy;
- whether secrets or forbidden destinations appear in the call;
- whether a human must approve the exact payload;
- whether the approved call was modified, replayed, or executed twice;
- whether the tool's output is trying to instruct the agent;
- what evidence proves the final outcome.

MCP Security Gateway places that control point between an MCP client and the
tools it calls: a fixed built-in execution adapter, or real MCP servers behind
the gateway in [proxy mode](#proxy-mode-real-mcp-servers-behind-the-gateway). It supports
protocol-level `initialize`, `ping`, `tools/list`, and `tools/call`, then
applies deterministic controls before any side effect. Callers authenticate
with public demo keys or, in [OAuth mode](#oauth-resource-server-mode), with access tokens from an
external authorization server.

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
  Policy -->|low risk| Execute["Execution"]
  Policy -->|high risk| Approval["Maker-checker approval"]
  Approval --> Lease["One-time capability lease"]
  Lease --> Execute
  Policy -->|deny| Incident["Incident"]
  Execute --> Adapter["Built-in adapter"]
  Execute -->|pin re-checked| Upstream["Upstream MCP server"]
  Upstream --> Inspect["Output inspection"]
  Adapter --> Evidence["HMAC-chained evidence"]
  Inspect --> Evidence
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
repeatable. In [OAuth mode](#oauth-resource-server-mode) they are refused, and callers present
audience-bound access tokens instead. Production mode requires OAuth mode.

### Tool Manifest Trust

Tool names, descriptions, JSON schemas, required scopes, risk levels, and
annotations are fingerprinted. Candidate changes produce a field-level diff.
Security administrators can quarantine a drifted tool; a platform administrator
must explicitly restore its trust state.

MCP tool annotations are retained for interoperability and operator context, but
the gateway does not treat server-provided hints as authorization.

For upstream servers in [proxy mode](#proxy-mode-real-mcp-servers-behind-the-gateway), the gateway
also re-reads each tool's definition on every call and again just before
forwarding, quarantines a new tool whose definition already carries hidden
instructions, and withholds tool output that reads like instructions to the
agent.

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

![MCP Security Gateway module launcher with live status for each module](docs/assets/gateway-dashboard.png)

The dashboard opens on a module launcher: one tile per module, each with a live
status such as pending approvals or the last Attack Lab score. A tile opens that
module on its own screen; **All modules**, `Esc`, or the browser Back button
returns to the launcher, and each module has a direct link such as
`/dashboard#traffic`. The credential field stays in the top bar so roles can be
switched from any module.

The modules provide:

- live MCP policy and execution traffic, with the decision reason on every row
  and an expandable trace of each policy control;
- tool trust registry with manifest fingerprints, and **Sync upstream** with
  the pinned and served descriptions side by side;
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

### 5. A poisoned upstream server caught

![A rug pull caught by the gateway: the pinned description next to the poisoned one the upstream serves now, with its hidden text decoded](docs/assets/upstream-rug-pull.jpg)

In [proxy mode](#proxy-mode-real-mcp-servers-behind-the-gateway) the gateway pins each upstream
tool on review. When the server later swaps a description, the next call is
blocked and the tool quarantined. **Tool trust** shows the pinned description
next to the one the server serves now, and decodes the instructions hidden in
invisible Unicode tag characters.

## API Surface

### MCP protocol boundary

- `POST /mcp` — `initialize`, `ping`, `tools/list`, `tools/call`, and
  `notifications/*` (see [Connect Your Client](#connect-your-client))
- `GET /.well-known/oauth-protected-resource/mcp` — RFC 9728
  protected-resource metadata, in [OAuth mode](#oauth-resource-server-mode) only

### Operator API

- `GET /health`
- `GET /me`
- `GET /mcp-servers`
- `GET /policies`
- `GET /tool-registry`
- `POST /tool-registry/{tool_id}/verify`
- `POST /tool-registry/{tool_id}/restore`
- `GET /upstreams`
- `POST /upstreams/{server_id}/sync`
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
| policy violation (secret, scope, traversal, production admin, changed upstream tool) | `denied` | `true` |
| upstream tool output that reads like instructions to the agent ([proxy mode](#proxy-mode-real-mcp-servers-behind-the-gateway)) | `response_blocked` | `true` |

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

### n8n (MCP Client Tool)

- **Endpoint:** `http://127.0.0.1:8000/mcp?tool_names=underscore`
- **Server Transport:** HTTP Streamable
- **Authentication:** Bearer Auth, with the token `msg-ops-demo`

n8n passes MCP tool names to the model unchanged, so an agent with an OpenAI
model needs the parameter. The next section explains why.

### Tool names for function-calling models

MCP tool names may contain dots: `kb.search` is a valid MCP name. OpenAI and
Azure OpenAI accept only function names that match `^[a-zA-Z0-9_-]{1,64}$`. A
client that passes MCP names to the model unchanged fails on its first model
request. On 2026-11-25, an n8n Cloud 2.49.6 agent with an OpenAI model got:
`Invalid 'tools[0].function.name': string does not match pattern`.

With `/mcp?tool_names=underscore`:

- `tools/list` returns aliases such as `kb_search`, `repo_write_file` and
  `ops_restart_service`, and keeps the canonical name in
  `_meta["gateway/canonicalName"]`;
- `tools/call` accepts the alias or the canonical name and resolves the alias
  before any policy runs. Manifests, approvals and the audit trail record only
  the canonical name;
- each character outside `[a-zA-Z0-9_-]` becomes `_`. A name longer than 64
  characters keeps its first 55 characters, then `_` and 8 hex characters of
  its SHA-256;
- when two tools would share an alias, neither gets it. Both drop out of the
  underscore listing and stay callable by their canonical names. Giving the
  alias to one of them would make the choice depend on which other tools
  exist, so after an upstream sync a cached alias could reach a different tool.

Without the parameter, tool names are unchanged.

### Protocol contract

- negotiates MCP `2025-11-25` or `2025-06-18`; a client offering any other
  revision is answered with `2025-11-25`, the latest supported one;
- `2025-03-26` is not offered because it requires JSON-RPC batch support;
- notifications such as `notifications/initialized` return `202 Accepted`
  with no body;
- requests without an `id`, or with a `null` id, are rejected with `400`;
- an `MCP-Protocol-Version` header, when sent, must name a supported revision;
- capabilities advertise `tools.listChanged: false`, because there is no
  server-to-client stream (`GET /mcp` returns `405`);
- `tool_names` accepts `dotted` (the default) or `underscore`; any other value
  is rejected with `400`.

Verification boundary, as run on 2026-11-17 against a local gateway on a fresh
database (the last two rows: 2026-11-25):

| Client | What was run | Result |
| --- | --- | --- |
| MCP Python SDK 2.3.0 | the snippet above, extended to one call per decision | negotiated `2025-11-25`; `tools/list` returned the three tools; `kb.search` → `executed`, `repo.write_file` → `approval_required`, `repo.write_file` with a secret → `denied` (`isError: true`); `ping` answered |
| Claude Code 2.1.248 | the `claude mcp add` command above, then `claude mcp list` | `✔ Connected` |
| Cursor, VS Code | not run | the snippets follow each client's documented remote HTTP format |
| n8n Cloud 2.49.6, AI Agent with OpenAI `gpt-5-mini` | MCP Client Tool on the public sandbox, before `tool_names` existed | `tools/list` returned the three tools; the first model request failed, because OpenAI rejected `kb.search` as a function name |
| MCP Python SDK 2.3.0 | seven calls covering every decision, through `?tool_names=underscore`, against a local sandbox | all five aliases are valid function names; every decision matched the canonical names, including `response_blocked` and the denial after a changed upstream tool |

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

With `MSG_AUTH_MODE=oauth`, the gateway is an OAuth 2.1 resource server, as
MCP 2025-11-25 authorization describes it. It validates access tokens from an
external authorization server, and never issues them:

- **Discovery.** It publishes RFC 9728 protected-resource metadata at
  `/.well-known/oauth-protected-resource/mcp`, and a `401` challenge points to
  it.
- **Signatures.** They are checked against the authorization server's JWKS,
  with asymmetric algorithms only.
- **Claims.** `iss`, `exp`, `nbf` and `sub` are checked, and `aud` must name
  the gateway (RFC 8707).
- **Scopes.** A missing scope gets `403 insufficient_scope`.
- **Subjects.** Each token subject maps explicitly to a gateway user.
- **Boundaries.** The token is never passed through, and the static demo keys
  are refused. Production refuses to start in static mode.

It has been run against a local Keycloak realm from the compose profile
`oauth`, on Keycloak 26.4.5 and again on 26.8.2-2.
**[docs/OAUTH.md](docs/OAUTH.md)** has:

- the configuration;
- a walkthrough with scripted tokens;
- what was observed, including Claude Code's discovery attempt;
- what this mode does not include.

## Proxy Mode: Real MCP Servers Behind the Gateway

The gateway can sit in front of real MCP servers that speak Streamable HTTP.
Agents connect to the gateway only. Every upstream call goes through the same
control path as a built-in one before it is forwarded. On top of that, the
gateway:

- **pins each upstream tool on review,** and quarantines a new tool whose
  definition already hides instructions;
- **re-checks the definition on every call** and again just before
  forwarding, so it catches a rug pull even between approval and execution;
- **withholds output** that reads like instructions to the agent
  (`response_blocked`);
- **lists only verified tools,** and never passes the caller's credentials
  upstream.

The animation at the top of this page is this run, recorded in the console.

```powershell
python examples/poisoned_server.py        # a deliberately malicious server on :8100
$env:MSG_UPSTREAMS = "examples/upstreams.json"
python -m uvicorn mcp_security_gateway.main:app --port 8000
```

**[docs/PROXY.md](docs/PROXY.md)** has:

- the configuration;
- the example server;
- a step-by-step run with the MCP Python SDK as the agent;
- the limits.

The checks are patterns, not a proof.

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

Compose sets up both containers like this:
- the API is bound to loopback, and Redis stays on the internal network;
- both containers drop every Linux capability;
- the API runs as a non-root user with a read-only root filesystem, and mounts
  only the persistent SQLite data volume;
- Redis runs as its own user, so it needs no capability to switch users.

The image holds only what the gateway needs at run time. Debian security
updates are applied when it is built, and pip, setuptools and wheel are removed
after the install. The local fallback audit key is still only a development
convenience; configure a managed secret for any non-local runtime.

**CI checks the image on every pull request** (the `docker` job):
- it builds the image;
- it scans it with Trivy, and fails on any HIGH or CRITICAL vulnerability that
  has a fix;
- it starts the image with Redis;
- `scripts/docker_smoke.py` checks `/health` and one MCP call.

**Some findings have no fix yet.** A scan on 2026-11-18 reported 47 HIGH and no
CRITICAL findings for which Debian has no fix yet, in util-linux, ncurses,
perl, systemd and SQLite libraries. Three of them are in `libsqlite3-0`, which
the gateway uses.

**`docker compose down -v` deletes the `gateway-data` volume and the gateway's
database with it.** To stop the stack and keep the data, use
`docker compose down`.

## Public Sandbox

The sandbox runs at https://mcp-security-gateway-sandbox.onrender.com.

`deploy/demo/Dockerfile` builds a sandbox that is safe to put online. It runs the
gateway and the poisoned example server in one container, and starts with
`MSG_ENVIRONMENT=sandbox` and the public demo keys:

```powershell
docker build -f deploy/demo/Dockerfile -t mcp-security-gateway-sandbox .
docker run --rm -p 127.0.0.1:8010:8000 mcp-security-gateway-sandbox
```

Open `http://127.0.0.1:8010/dashboard`. A strip at the top names the public
keys. It also has a button that makes the test server swap a tool description,
and a button that resets the sandbox.

**Sandbox mode adds these limits to the gateway's own:**
- **Per address:** 120 requests a minute per client address
  (`MSG_SANDBOX_IP_LIMIT_PER_MINUTE`).
- **Proxied addresses:** behind a proxy, the address comes from the
  `X-Forwarded-For` entries that trusted proxies appended
  (`MSG_TRUSTED_PROXY_HOPS`). An entry the client wrote itself never counts.
  `GET /sandbox` shows callers the address the gateway sees for them and how
  many entries arrived. After a deploy, a private address there means the
  setting is too low.
- **Request bodies:** capped at 64 KiB. A body without `Content-Length` gets
  `411`, so chunked encoding cannot skip the cap.
- **Resets:** all data resets every 60 minutes (`MSG_SANDBOX_RESET_MINUTES`), on
  every start, and whenever the SQLite file passes 16 MiB
  (`MSG_SANDBOX_MAX_DB_BYTES`). Each reset also resets the test server.
- **Controls:** only a security or platform admin can use them. A manual reset
  can run once a minute.
- **The test server:** the gateway reaches it on loopback only, and any other
  address is refused at start.

[`render.yaml`](render.yaml) describes the sandbox as a free Render web service.
Nothing deploys from it until the repository owner creates a Blueprint.
`scripts/sandbox_smoke.py` checks the image in CI. It syncs the test server,
makes a clean call, swaps the tool and checks that the next call is denied.

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

[`tests/test_oauth.py`](tests/test_oauth.py) signs tokens with keys generated
during the run, so it needs no authorization server.
[`tests/test_upstream.py`](tests/test_upstream.py) holds the poisoned example
server in memory. [docs/OAUTH.md](docs/OAUTH.md#tests) and
[docs/PROXY.md](docs/PROXY.md#tests) list what each one covers.

`scripts/mutation_check.py` checks that the tests protect each guard. It
removes one guard at a time, runs the matching test file, and restores the
source byte for byte. There are eleven mutations for proxy mode, nine for OAuth
mode and nine for the sandbox, and each one must make a test fail:

```powershell
python scripts/mutation_check.py          # or: proxy, oauth, sandbox
```

CI runs it on every pull request and on every push to `main`.

`scripts/e2e_proxy.py` runs proxy mode end to end, over real HTTP. It starts
the poisoned example server and the gateway on free loopback ports, uses the
official MCP Python SDK as the agent, and asserts every step from the first sync
to the rug pull. CI runs it too:

```powershell
python -m pip install -e ".[e2e]"
python scripts/e2e_proxy.py
```

## Production-shaped, Not Production-ready

This repository proves the security control path. It intentionally does not
claim to be a drop-in enterprise gateway.

Current portfolio boundaries:

- SQLite persistence rather than managed PostgreSQL and migrations;
- public local demo credentials by default. OAuth resource-server mode
  validates tokens from an external authorization server, but has been run only
  against a local Keycloak realm, not a corporate identity provider;
- upstream MCP servers over Streamable HTTP only, configured by the operator, and
  injection checks that are patterns rather than a guarantee; otherwise a fixed
  in-process execution adapter rather than arbitrary remote MCP server
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
- caught upstream rug pull: [docs/assets/upstream-rug-pull.jpg](docs/assets/upstream-rug-pull.jpg)
- proxy mode, step by step: [docs/assets/proxy-mode-demo.gif](docs/assets/proxy-mode-demo.gif)
- proxy mode: [docs/PROXY.md](docs/PROXY.md)
- OAuth resource-server mode: [docs/OAUTH.md](docs/OAUTH.md)
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
