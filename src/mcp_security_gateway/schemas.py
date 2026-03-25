from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class UserOut(BaseModel):
    id: str
    name: str
    role: str
    organization_id: str


class MCPServerOut(BaseModel):
    id: str
    name: str
    environment: str
    sensitivity: str
    allowed_scopes: str


class PolicyOut(BaseModel):
    id: str
    name: str
    mode: str
    description: str


class RequestIn(BaseModel):
    mcp_server_id: str
    tool_name: str
    requested_scope: str
    justification: str = Field(min_length=10, max_length=280)
    estimated_tokens: int = Field(ge=1, le=200000)
    arguments: dict[str, Any] = Field(default_factory=dict)


class RequestOut(BaseModel):
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


class ApprovalOut(BaseModel):
    id: str
    request_id: str
    organization_id: str
    status: str
    reason: str
    decided_by: str | None


class ApprovalDecisionIn(BaseModel):
    decision: str


class IncidentOut(BaseModel):
    id: str
    request_id: str
    organization_id: str
    severity: str
    summary: str


class HealthOut(BaseModel):
    service: str
    database_backend: str
    rate_limit_backend: str
    users: int
    servers: int
    requests: int
    pending_approvals: int
    incidents: int
