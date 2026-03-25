# LinkedIn Post

## Post

I built an MCP security gateway with FastAPI, policy enforcement, approval routing, secret redaction, audit logs, and Redis-ready rate limits.

The goal was simple: not another agent demo, but the guardrail layer around MCP tool access in production.

This MVP proves three paths end-to-end:
1. low-risk read request -> approved
2. high-risk write request -> routed to approval
3. privileged production action -> blocked and escalated to an incident

What it includes:
- FastAPI backend
- deterministic policy engine
- redacted audit logging
- approval queue
- incident creation
- SQLite persistence
- Redis-ready rate limiting

Repo:
https://github.com/danieloza/mcp-security-gateway

#Python #FastAPI #MCP #AISecurity #Backend #PlatformEngineering

## Carousel Order

1. `screen-04-product-proof.png`
2. `screen-01-dashboard.png`
3. `screen-02-health-proof.png`
4. `screen-03-ops-proof.png`

## Featured Blurb

Security gateway for MCP servers with auth, policy enforcement, approvals, rate limits, incident creation, and redacted audit logs.
