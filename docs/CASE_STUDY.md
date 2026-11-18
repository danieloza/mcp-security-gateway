# Case Study

## Problem

AI agents can discover MCP tools whose descriptions imply what they do, but the
agent cannot be the final authority for access. Tool metadata may change after
review, high-risk arguments may be substituted after approval, and a valid
identity may still request a scope or destination outside its operating
boundary. An upstream server can change a tool's description after review, or
answer with text written to steer the agent.

## Engineering Decision

MCP Security Gateway makes tool execution conditional on five independent
controls:

1. tenant-bound workload identity;
2. a pinned tool manifest fingerprint;
3. deterministic scope, DLP, rate, and environment policy;
4. maker-checker approval bound to the exact request digest;
5. a one-time capability lease consumed immediately before execution.

Low-risk knowledge access can execute automatically. Sandboxed writes pause for
approval. Production administration, manifest drift, secret-bearing arguments,
and forbidden destinations are denied before reaching the execution adapter.

The same path extends to real MCP servers. Each upstream tool is pinned on
review and checked against the pin on every call and again before forwarding.
Its output is inspected before it reaches the agent. Callers can also present
OAuth 2.1 access tokens issued for the gateway as their audience.

## Outcome

The project demonstrates that an MCP security boundary should control execution,
not merely label a request as safe. The operator can show the full transition
from protocol call through policy, approval, execution, and tamper-evident
evidence.

## Deliberate Boundary

The repository uses SQLite, a fixed in-process adapter, and operator-configured
Streamable HTTP upstreams, so the complete security sequence remains
deterministic and free to run. OAuth mode has been run only against a local
Keycloak realm. It does not claim `stdio` upstreams, upstream credentials, a
production identity provider, immutable archival, or multi-region resilience.
