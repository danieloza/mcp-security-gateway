# Architecture

MCP Security Gateway sits between agent runtimes and MCP servers.

## Core flow

1. An authenticated caller submits a tool request.
2. The gateway identifies the caller role and tenant context from the API key.
3. The policy engine evaluates target server, scope, tool name, rate limits, and argument sensitivity.
4. The gateway either approves, routes to approval, or blocks and creates an incident.
5. The gateway persists a redacted audit record for later review.

## Current primitives

- API-key based auth contexts
- deterministic policy evaluation
- Redis-ready rate limiting with in-memory fallback
- SQLite-backed request, approval, and incident history
- operator dashboard for demo and recruiting walkthroughs
