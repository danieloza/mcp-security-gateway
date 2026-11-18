# Proxy Mode: Real MCP Servers Behind the Gateway

This is the detailed reference. The
[README](../README.md#proxy-mode-real-mcp-servers-behind-the-gateway) has the
summary, and [API examples](API_EXAMPLES.md#proxy-mode-sync-an-upstream-server)
show the raw answers.

The gateway can sit in front of real MCP servers that speak Streamable HTTP.
Agents connect to the gateway only. Every call to an upstream tool goes through
the same path as a built-in one: identity, manifest pin, scope, rate limit,
argument DLP, risk, maker-checker approval, one-time lease, and evidence. Then it
is forwarded.

![A rug pull caught by the gateway: the pinned description next to the poisoned one the upstream serves now, with its hidden text decoded](assets/upstream-rug-pull.jpg)

## A call, step by step

```mermaid
flowchart TD
  Call["Agent: tools/call notes.search_notes"] --> Read["The gateway reads the upstream's current definition"]
  Read --> Pin{"Same as the pin?"}
  Pin -->|changed| Pulled["denied: tool quarantined, critical incident"]
  Pin -->|unreachable| Closed["denied: fails closed, incident"]
  Pin -->|same| Policy{"Policy: scope, rate limit, DLP, risk"}
  Policy -->|violation| Denied["denied, with an incident"]
  Policy -->|high risk| Approval["approval_required: a checker approves, the maker claims a one-time lease"]
  Policy -->|low risk| Execute["Execute"]
  Approval --> Execute
  Execute --> Recheck{"Still the same as the pin?"}
  Recheck -->|changed| Stopped["stopped: tool quarantined, critical incident"]
  Recheck -->|same| Forward["Forward tools/call: the evaluated arguments only, no caller credentials"]
  Forward --> Inspect{"Output reads like instructions to the agent?"}
  Inspect -->|yes| Withheld["response_blocked for the agent, output_withheld for operators, incident"]
  Inspect -->|no| Executed["executed, with secrets redacted"]
```

## What the gateway adds

- **Pinning on review.** A security or platform admin runs
  `POST /upstreams/{id}/sync`, or **Sync upstream** in the Tool trust module.
  Each new tool is pinned under `<prefix>.<name>`: its name, description, input
  schema and annotations. A new tool whose description already carries hidden
  instructions is quarantined on first sight ("tool poisoning").
- **Rug-pull detection, twice per call.** The gateway re-reads the upstream's
  definition of a tool on every call, and again just before forwarding.
  - A changed definition quarantines the tool and blocks the call. So does a
    change between approval and execution.
  - The console shows the pinned and served descriptions side by side. Text
    hidden in Unicode tag characters is decoded, and other invisible characters
    are shown as code points.
- **Output inspection.** Before a tool's output reaches the agent, it is checked
  for:
  - invisible or tag characters;
  - instruction overrides;
  - concealment ("do not tell the user");
  - coaxing towards secret files such as `~/.ssh` or `mcp.json`;
  - `<important>`-style blocks;
  - redirection to other tools.

  On a match, the agent gets `response_blocked` with the finding types and a
  digest, never the text. An incident and an audit event are recorded, and the
  request's execution status is `output_withheld`, so **Live traffic** shows it
  apart from a plain execution. Secrets in clean output are redacted, as for
  built-in tools.
- **Quarantined tools are not listed.** `tools/list` shows verified tools only,
  so a poisoned description never reaches the agent.
- **A small upstream client of its own,** on `httpx`:
  - it follows no redirects;
  - it caps responses at 1 MiB and times out after 10 s;
  - it reads JSON and SSE answers.

  It never carries the caller's credentials, because it has no access to them.
- **Fail closed.** An unreachable upstream blocks the call.

**Configuration:** `MSG_UPSTREAMS` points to a JSON list, for example
[`examples/upstreams.json`](../examples/upstreams.json):
- `id`, `name`, `url`, `prefix`, `organization_id`, `scope`;
- `default_risk`, and per-tool `risk`.

The operator configures upstreams. An agent can never add or address one.

## Try it with the poisoned example server

![Proxy mode in the console: an upstream server synced, three agent calls, a rug pull blocked, and the diff with its hidden text decoded](assets/proxy-mode-demo.gif)

[`examples/poisoned_server.py`](../examples/poisoned_server.py) is a deliberately
malicious MCP server, a test fixture that runs on loopback and touches no file
or network.
- `search_notes` returns a note that tells the agent to read `~/.ssh/id_rsa`
  and keep quiet.
- `POST /rugpull` swaps its description for a poisoned one, with hidden tag
  characters.
- `export_notes` is configured as high-risk.

```powershell
python examples/poisoned_server.py                      # :8100
$env:MSG_UPSTREAMS = "examples/upstreams.json"
python -m uvicorn mcp_security_gateway.main:app --port 8000
```

**As run on 2026-11-17,** with the MCP Python SDK 2.3.0 as the agent and a
fresh database:

| Step | What the agent got |
| --- | --- |
| before any sync | only the built-in tools |
| sync | `notes.search_notes` and `notes.export_notes` pinned |
| `search_notes` "rota" | `executed`, with the note |
| `search_notes` "deploy" | `response_blocked` (`instruction_override`, `concealment`, `secret_file_coaxing`); no trace of the note in the result |
| `export_notes` | `approval_required` |
| after `POST /rugpull`, no sync | `denied`: "upstream tool definition changed since it was pinned"; the tool quarantined |
| sync again | `quarantined (rug_pull)` with the diff, and no second incident |

**These checks are patterns, not a proof.** A determined author can phrase an
injection that none of these rules knows. A match withholds the text; the
absence of a match only means none of these patterns was found.

**Not covered:**
- `stdio` upstreams;
- upstream credentials;
- server-to-client streams from upstreams.

## Tests

The tests in [`tests/test_upstream.py`](../tests/test_upstream.py) hold the poisoned
example server in memory. They cover:
- pinning on sync, and quarantine on first sight;
- a rug pull caught by a sync, by a call, and between approval and execution;
- withheld output, and redacted secrets in clean output;
- an unreachable upstream, which fails closed;
- the upstream client: no redirects, the size cap, SSE answers, timeouts, and
  no forwarded `Authorization`;
- each injection pattern.

`python scripts/mutation_check.py proxy` removes each of ten proxy guards in
turn and expects a failing test every time. CI runs it on every pull request.

[`scripts/e2e_proxy.py`](../scripts/e2e_proxy.py) repeats the run above over real HTTP,
with the MCP Python SDK as the agent, and asserts each step. CI runs it as well.
