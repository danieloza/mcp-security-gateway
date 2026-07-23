from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class UserOut(StrictModel):
    id: str
    name: str
    role: str
    organization_id: str


class MCPServerOut(StrictModel):
    id: str
    organization_id: str
    name: str
    environment: str
    sensitivity: str
    allowed_scopes: str
    trust_status: str


class PolicyOut(StrictModel):
    id: str
    organization_id: str
    name: str
    mode: str
    description: str
    version: str


class ToolManifestOut(StrictModel):
    id: str
    organization_id: str
    mcp_server_id: str
    name: str
    description: str
    required_scope: str
    risk_level: str
    input_schema: dict[str, Any]
    annotations: dict[str, Any]
    manifest_digest: str
    trust_status: str
    verified_at: str


class RequestIn(StrictModel):
    mcp_server_id: str = Field(min_length=3, max_length=80, pattern=r"^[a-z0-9_.-]+$")
    tool_name: str = Field(min_length=3, max_length=120, pattern=r"^[a-z0-9_.-]+$")
    requested_scope: str = Field(min_length=3, max_length=120, pattern=r"^[a-z0-9:_-]+$")
    justification: str = Field(min_length=10, max_length=280)
    estimated_tokens: int = Field(ge=1, le=200_000)
    arguments: dict[str, Any] = Field(default_factory=dict)


class RequestOut(StrictModel):
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


class ApprovalOut(StrictModel):
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


class ApprovalDecisionIn(StrictModel):
    decision: Literal["approved", "denied"]


class ApprovalDecisionOut(StrictModel):
    approval: ApprovalOut
    capability_lease: str | None
    expires_at: str | None


class ApprovedExecutionIn(StrictModel):
    arguments: dict[str, Any]
    capability_lease: str = Field(min_length=32, max_length=256)


class ExecutionOut(StrictModel):
    id: str
    request_id: str
    organization_id: str
    tool_name: str
    status: str
    result_json: str
    result_digest: str
    latency_ms: int
    created_at: str


class IncidentOut(StrictModel):
    id: str
    request_id: str
    organization_id: str
    severity: str
    summary: str
    created_at: str


class ManifestCandidateIn(StrictModel):
    name: str = Field(min_length=3, max_length=120)
    description: str = Field(min_length=3, max_length=500)
    input_schema: dict[str, Any]
    annotations: dict[str, Any]
    enforce_quarantine: bool = False


class ManifestVerificationOut(StrictModel):
    tool_id: str
    status: str
    expected_digest: str
    candidate_digest: str
    changed_fields: list[str]
    quarantine_recommended: bool


class AttackLabCaseOut(StrictModel):
    id: str
    name: str
    expected: str
    observed: str
    passed: bool
    evidence: str


class AttackLabOut(StrictModel):
    passed: int
    total: int
    cases: list[AttackLabCaseOut]
    executed_at: str


class EvidenceOut(StrictModel):
    request: RequestOut
    approval: ApprovalOut | None
    executions: list[ExecutionOut]
    audit_events: list[dict[str, Any]]
    chain_valid: bool
    evidence_digest: str


class MCPRequestIn(StrictModel):
    jsonrpc: Literal["2.0"]
    id: str | int | None = None
    method: str = Field(min_length=1, max_length=120)
    params: dict[str, Any] = Field(default_factory=dict)


class HealthOut(StrictModel):
    service: str
    environment: str
    database_backend: str
    rate_limit_backend: str
    api_key_storage: str
    protocol: str
    users: int
    servers: int
    tools: int
    requests: int
    pending_approvals: int
    incidents: int
    executions: int
