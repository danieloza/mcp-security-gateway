from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class User:
    id: str
    name: str
    role: str
    organization_id: str
    api_key: str


@dataclass(slots=True)
class MCPServer:
    id: str
    name: str
    environment: str
    sensitivity: str
    allowed_scopes: str


@dataclass(slots=True)
class Policy:
    id: str
    name: str
    mode: str
    description: str


@dataclass(slots=True)
class GatewayRequest:
    id: str
    organization_id: str
    requested_by: str
    mcp_server_id: str
    tool_name: str
    requested_scope: str
    justification: str
    estimated_tokens: int
    status: str
    policy_id: str
    risk_reason: str
    redacted_arguments: str


@dataclass(slots=True)
class Approval:
    id: str
    request_id: str
    organization_id: str
    status: str
    reason: str
    decided_by: str | None


@dataclass(slots=True)
class Incident:
    id: str
    request_id: str
    organization_id: str
    severity: str
    summary: str
