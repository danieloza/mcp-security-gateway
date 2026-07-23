from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class User:
    id: str
    name: str
    role: str
    organization_id: str
    api_key_hash: str


@dataclass(slots=True)
class MCPServer:
    id: str
    organization_id: str
    name: str
    environment: str
    sensitivity: str
    allowed_scopes: str
    trust_status: str


@dataclass(slots=True)
class Policy:
    id: str
    organization_id: str
    name: str
    mode: str
    description: str
    version: str


@dataclass(slots=True)
class ToolManifest:
    id: str
    organization_id: str
    mcp_server_id: str
    name: str
    description: str
    required_scope: str
    risk_level: str
    input_schema: str
    annotations: str
    manifest_digest: str
    trust_status: str
    verified_at: str


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
    policy_version: str
    risk_reason: str
    policy_trace: str
    redacted_arguments: str
    arguments_digest: str
    manifest_digest: str
    request_digest: str
    execution_status: str
    created_at: str
    updated_at: str


@dataclass(slots=True)
class Approval:
    id: str
    request_id: str
    organization_id: str
    status: str
    reason: str
    request_digest: str
    requested_by: str
    decided_by: str | None
    created_at: str
    decided_at: str | None


@dataclass(slots=True)
class CapabilityLease:
    id: str
    request_id: str
    organization_id: str
    token_hash: str
    request_digest: str
    issued_by: str
    expires_at: str
    used_at: str | None
    created_at: str


@dataclass(slots=True)
class Incident:
    id: str
    request_id: str
    organization_id: str
    severity: str
    summary: str
    created_at: str


@dataclass(slots=True)
class ExecutionRecord:
    id: str
    request_id: str
    organization_id: str
    tool_name: str
    status: str
    result_json: str
    result_digest: str
    latency_ms: int
    created_at: str


@dataclass(slots=True)
class AuditEvent:
    id: str
    organization_id: str
    event_type: str
    subject_id: str
    actor_id: str
    payload_json: str
    previous_digest: str
    event_digest: str
    created_at: str
