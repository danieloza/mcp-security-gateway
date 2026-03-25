from __future__ import annotations

import json
import re
from dataclasses import dataclass

from mcp_security_gateway.models import Approval, GatewayRequest, Incident, MCPServer, Policy, User
from mcp_security_gateway.repository import SQLiteRepository
from mcp_security_gateway.state import RateLimitStore


SECRET_PATTERN = re.compile(r"(token|secret|password|api[_-]?key)", re.IGNORECASE)


@dataclass(slots=True)
class AuthContext:
    user: User


class GatewayService:
    def __init__(self, repo: SQLiteRepository, rate_limits: RateLimitStore) -> None:
        self.repo = repo
        self.rate_limits = rate_limits

    def build_auth_context(self, api_key: str) -> AuthContext | None:
        user = self.repo.get_user_by_api_key(api_key)
        return AuthContext(user) if user else None

    def health_snapshot(self) -> dict[str, int | str]:
        counts = self.repo.health_counts()
        return {
            "service": "mcp-security-gateway",
            "database_backend": "sqlite",
            "rate_limit_backend": self.rate_limits.backend_name,
            "users": counts["users"],
            "servers": counts["servers"],
            "requests": counts["requests"],
            "pending_approvals": counts["approvals"],
            "incidents": counts["incidents"],
        }

    def list_servers(self, auth: AuthContext) -> list[MCPServer]:
        return self.repo.list_servers()

    def list_policies(self, auth: AuthContext) -> list[Policy]:
        return self.repo.list_policies()

    def list_requests(self, auth: AuthContext) -> list[GatewayRequest]:
        return self.repo.list_requests(auth.user.organization_id)

    def get_request(self, auth: AuthContext, request_id: str) -> GatewayRequest:
        request = self.repo.get_request(request_id)
        if not request or request.organization_id != auth.user.organization_id:
            raise ValueError(f"Unknown request '{request_id}'.")
        return request

    def list_approvals(self, auth: AuthContext) -> list[Approval]:
        return self.repo.list_approvals(auth.user.organization_id)

    def list_incidents(self, auth: AuthContext) -> list[Incident]:
        return self.repo.list_incidents(auth.user.organization_id)

    def submit_request(
        self,
        auth: AuthContext,
        mcp_server_id: str,
        tool_name: str,
        requested_scope: str,
        justification: str,
        estimated_tokens: int,
        arguments: dict[str, object],
    ) -> GatewayRequest:
        server = self.repo.get_server(mcp_server_id)
        if not server:
            raise ValueError(f"Unknown MCP server '{mcp_server_id}'.")

        allowed = {item.strip() for item in server.allowed_scopes.split(",")}
        if requested_scope not in allowed:
            raise PermissionError(f"Requested scope '{requested_scope}' is not allowed for server '{mcp_server_id}'.")

        hits = self.rate_limits.increment(auth.user.api_key)
        if hits > 5:
            request = self._new_request(auth, server, tool_name, requested_scope, justification, estimated_tokens, arguments)
            request.status = "blocked"
            request.policy_id = "pol_hard_block"
            request.risk_reason = "rate limit exceeded"
            self.repo.save_request(request)
            self.repo.save_incident(
                Incident(
                    id=self._next_id("inc", len(self.repo.list_incidents(auth.user.organization_id)) + 1),
                    request_id=request.id,
                    organization_id=auth.user.organization_id,
                    severity="high",
                    summary="Caller exceeded gateway rate limits.",
                )
            )
            return request

        request = self._new_request(auth, server, tool_name, requested_scope, justification, estimated_tokens, arguments)

        if server.environment == "production" and requested_scope == "ops:admin":
            request.status = "blocked"
            request.policy_id = "pol_hard_block"
            request.risk_reason = "privileged production operations are hard-blocked"
            self.repo.save_request(request)
            self.repo.save_incident(
                Incident(
                    id=self._next_id("inc", len(self.repo.list_incidents(auth.user.organization_id)) + 1),
                    request_id=request.id,
                    organization_id=auth.user.organization_id,
                    severity="critical",
                    summary="Blocked privileged production operation through MCP gateway.",
                )
            )
            return request

        if server.sensitivity in {"high", "critical"} or requested_scope.endswith(":write") or "delete" in tool_name:
            request.status = "awaiting_approval"
            request.policy_id = "pol_approval_gate"
            request.risk_reason = "high-risk tool access requires security review"
            self.repo.save_request(request)
            self.repo.save_approval(
                Approval(
                    id=self._next_id("apr", len(self.repo.list_approvals(auth.user.organization_id)) + 1),
                    request_id=request.id,
                    organization_id=auth.user.organization_id,
                    status="pending",
                    reason=request.risk_reason,
                    decided_by=None,
                )
            )
            return request

        request.status = "approved"
        request.policy_id = "pol_default_allow"
        request.risk_reason = "within allowed scope and risk envelope"
        self.repo.save_request(request)
        return request

    def decide_approval(self, auth: AuthContext, approval_id: str, decision: str) -> Approval:
        if auth.user.role not in {"security_admin", "platform_admin"}:
            raise PermissionError("Only security or platform admins can decide approvals.")
        if decision not in {"approved", "denied"}:
            raise ValueError("Decision must be either 'approved' or 'denied'.")

        approval = self.repo.get_approval(approval_id)
        if not approval or approval.organization_id != auth.user.organization_id:
            raise ValueError(f"Unknown approval '{approval_id}'.")

        approval = self.repo.update_approval(approval_id, decision, auth.user.id)
        self.repo.update_request_status(approval.request_id, "approved" if decision == "approved" else "blocked")

        if decision == "denied":
            self.repo.save_incident(
                Incident(
                    id=self._next_id("inc", len(self.repo.list_incidents(auth.user.organization_id)) + 1),
                    request_id=approval.request_id,
                    organization_id=auth.user.organization_id,
                    severity="medium",
                    summary="Request denied during approval review.",
                )
            )
        return approval

    def _new_request(
        self,
        auth: AuthContext,
        server: MCPServer,
        tool_name: str,
        requested_scope: str,
        justification: str,
        estimated_tokens: int,
        arguments: dict[str, object],
    ) -> GatewayRequest:
        request_index = len(self.repo.list_requests(auth.user.organization_id)) + 1
        return GatewayRequest(
            id=self._next_id("req", request_index),
            organization_id=auth.user.organization_id,
            requested_by=auth.user.id,
            mcp_server_id=server.id,
            tool_name=tool_name,
            requested_scope=requested_scope,
            justification=justification,
            estimated_tokens=estimated_tokens,
            status="pending",
            policy_id="",
            risk_reason="",
            redacted_arguments=self._redact(arguments),
        )

    @staticmethod
    def _next_id(prefix: str, index: int) -> str:
        return f"{prefix}_{index:04d}"

    @staticmethod
    def _redact(arguments: dict[str, object]) -> str:
        def scrub(value: object) -> object:
            if isinstance(value, dict):
                return {
                    key: "[REDACTED]" if SECRET_PATTERN.search(key) else scrub(inner)
                    for key, inner in value.items()
                }
            if isinstance(value, list):
                return [scrub(item) for item in value]
            if isinstance(value, str) and SECRET_PATTERN.search(value):
                return "[REDACTED]"
            return value

        return json.dumps(scrub(arguments), sort_keys=True)
