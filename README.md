# MCP Security Gateway

> FastAPI gateway for governing MCP tool access with auth, policy enforcement, approvals, rate limiting, and audit-friendly request logs.

[![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-Security_Gateway-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![MCP](https://img.shields.io/badge/MCP-Guardrails-1F2937?style=for-the-badge)](#)

![MCP Security Gateway dashboard](docs/assets/gateway-dashboard.png)

## Overview

Teams want agents to call MCP tools in production. The missing layer is usually control:

- who is allowed to call which MCP server
- which tools require approval
- what happens when a request exceeds scope or rate limits
- how sensitive arguments are redacted before they hit logs
- how incidents are created when policy is violated

MCP Security Gateway models that missing layer as a backend-first service.

## What This Project Proves

- policy enforcement around MCP tool access, not just model inference
- deterministic guardrails for high-risk tools and privileged scopes
- approval routing for risky requests
- audit logs with secret redaction
- per-key rate limiting with Redis-ready state
- operator-friendly visibility into requests, incidents, and decisions

## API Surface

- `GET /health`
- `GET /me`
- `GET /mcp-servers`
- `GET /policies`
- `GET /requests`
- `GET /requests/{request_id}`
- `POST /requests`
- `GET /approvals`
- `POST /approvals/{approval_id}/decision`
- `GET /incidents`

## Quickstart

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -e .
pip install pytest httpx
uvicorn mcp_security_gateway.main:app --reload
```

Open:

- `http://127.0.0.1:8000/docs`
- `http://127.0.0.1:8000/dashboard`

## Demo API Keys

- gateway operator: `msg-ops-demo`
- security admin: `msg-security-demo`
- platform admin: `msg-platform-demo`

## Docker Compose Demo

```bash
docker compose up --build
```

This starts:

- API on `http://127.0.0.1:8000`
- Redis on `localhost:6379`

## Example Request

```powershell
curl -X POST http://127.0.0.1:8000/requests `
  -H "X-API-Key: msg-ops-demo" `
  -H "Content-Type: application/json" `
  -d "{\"mcp_server_id\":\"mcp_github\",\"tool_name\":\"repo.write_file\",\"requested_scope\":\"repo:write\",\"justification\":\"Apply a generated patch to an internal repository\",\"estimated_tokens\":1400,\"arguments\":{\"path\":\"secrets.txt\",\"api_key\":\"abcd1234secret\"}}"
```

## Testing

```bash
python -m pip install -e .
python -m pytest -q
```

## Proof Assets

What you can inspect immediately:

- dashboard proof: [`docs/assets/gateway-dashboard.png`](docs/assets/gateway-dashboard.png)
- architecture notes: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- case study: [`docs/CASE_STUDY.md`](docs/CASE_STUDY.md)
- short Polish interview version: [`docs/README_SHORT_PL.md`](docs/README_SHORT_PL.md)

## Verified Paths

- low-risk read request -> approved
- high-risk write request -> routed to approval
- privileged production action -> blocked and escalated to incident
- sensitive arguments are redacted before request records are persisted

## Interview Framing

MCP Security Gateway is a backend gateway for controlling MCP tool access. It models policy enforcement, approvals, incidents, rate limiting, and redacted audit logs. The goal was to show the control and security layer around agent tool access, not just model invocation.

## Architecture

- gateway API: [main.py](src/mcp_security_gateway/main.py)
- policy engine: [services.py](src/mcp_security_gateway/services.py)
- persistence layer: [repository.py](src/mcp_security_gateway/repository.py)
- architecture notes: [ARCHITECTURE.md](docs/ARCHITECTURE.md)
- case study: [CASE_STUDY.md](docs/CASE_STUDY.md)
- short Polish interview version: [README_SHORT_PL.md](docs/README_SHORT_PL.md)
