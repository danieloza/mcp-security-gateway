from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.responses import FileResponse, JSONResponse
from starlette.middleware.trustedhost import TrustedHostMiddleware

from mcp_security_gateway.config import (
    allowed_hosts,
    allowed_origins,
    is_production,
    max_request_bytes,
    redis_url,
)
from mcp_security_gateway.repository import SQLiteRepository, repository
from mcp_security_gateway.schemas import (
    ApprovalDecisionIn,
    ApprovalDecisionOut,
    ApprovalOut,
    ApprovedExecutionIn,
    AttackLabOut,
    EvidenceOut,
    ExecutionOut,
    HealthOut,
    IncidentOut,
    ManifestCandidateIn,
    ManifestVerificationOut,
    MCPRequestIn,
    MCPServerOut,
    PolicyOut,
    RequestIn,
    RequestOut,
    ToolManifestOut,
    UserOut,
)
from mcp_security_gateway.services import AuthContext, GatewayService
from mcp_security_gateway.state import RateLimitStore, build_rate_limit_store
from mcp_security_gateway.tool_registry import public_manifest


rate_limit_store = build_rate_limit_store(redis_url())


def get_repository() -> SQLiteRepository:
    return repository


def get_rate_limit_store() -> RateLimitStore:
    return rate_limit_store


def get_service(
    repo: SQLiteRepository = Depends(get_repository),
    rates: RateLimitStore = Depends(get_rate_limit_store),
) -> GatewayService:
    return GatewayService(repo, rates)


def get_current_auth(
    authorization: str | None = Header(default=None),
    x_api_key: str | None = Header(default=None),
    service: GatewayService = Depends(get_service),
) -> AuthContext:
    bearer: str | None = None
    if authorization:
        scheme, _, value = authorization.partition(" ")
        if scheme.lower() != "bearer" or not value:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authorization must use the Bearer scheme.",
            )
        bearer = value
    if bearer and x_api_key and bearer != x_api_key:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Conflicting authentication headers.",
        )
    credential = bearer or x_api_key
    if not credential:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization: Bearer credential.",
        )
    auth = service.build_auth_context(credential)
    if not auth:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credential.",
        )
    return auth


def _raise_service_error(exc: Exception) -> None:
    if isinstance(exc, PermissionError):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


def _mcp_tool_result(
    request_id: str | int | None,
    *,
    status_value: str,
    message: str,
    structured: dict[str, Any],
    is_error: bool = False,
) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "result": {
            "content": [{"type": "text", "text": message}],
            "structuredContent": {"status": status_value, **structured},
            "isError": is_error,
        },
    }


def create_app(
    repo: SQLiteRepository | None = None,
    rates: RateLimitStore | None = None,
) -> FastAPI:
    docs_url = None if is_production() else "/docs"
    openapi_url = None if is_production() else "/openapi.json"
    app = FastAPI(
        title="MCP Security Gateway",
        version="0.2.0",
        docs_url=docs_url,
        redoc_url=None,
        openapi_url=openapi_url,
    )
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=allowed_hosts())
    package_path = Path(__file__).parent
    dashboard_path = package_path / "dashboard.html"
    dashboard_css_path = package_path / "dashboard.css"
    dashboard_js_path = package_path / "dashboard.js"

    if repo is not None:
        app.dependency_overrides[get_repository] = lambda: repo
    if rates is not None:
        app.dependency_overrides[get_rate_limit_store] = lambda: rates

    @app.middleware("http")
    async def request_limits_and_security_headers(request: Request, call_next: Any) -> Any:
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                too_large = int(content_length) > max_request_bytes()
            except ValueError:
                return JSONResponse(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    content={"detail": "Invalid Content-Length header."},
                )
            if too_large:
                return JSONResponse(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    content={"detail": "Request body exceeds the gateway limit."},
                )
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; "
            "base-uri 'none'; form-action 'self'"
        )
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/", include_in_schema=False)
    def root() -> FileResponse:
        return FileResponse(dashboard_path, media_type="text/html")

    @app.get("/dashboard", include_in_schema=False)
    def dashboard() -> FileResponse:
        return FileResponse(dashboard_path, media_type="text/html")

    @app.get("/assets/dashboard.css", include_in_schema=False)
    def dashboard_css() -> FileResponse:
        return FileResponse(dashboard_css_path, media_type="text/css")

    @app.get("/assets/dashboard.js", include_in_schema=False)
    def dashboard_js() -> FileResponse:
        return FileResponse(dashboard_js_path, media_type="text/javascript")

    @app.get("/health", response_model=HealthOut)
    def health(service: GatewayService = Depends(get_service)) -> HealthOut:
        return HealthOut(**service.health_snapshot())

    @app.get("/me", response_model=UserOut)
    def me(auth: AuthContext = Depends(get_current_auth)) -> UserOut:
        return UserOut(
            id=auth.user.id,
            name=auth.user.name,
            role=auth.user.role,
            organization_id=auth.user.organization_id,
        )

    @app.get("/mcp-servers", response_model=list[MCPServerOut])
    def list_servers(
        auth: AuthContext = Depends(get_current_auth),
        service: GatewayService = Depends(get_service),
    ) -> list[MCPServerOut]:
        return [MCPServerOut(**asdict(item)) for item in service.list_servers(auth)]

    @app.get("/policies", response_model=list[PolicyOut])
    def list_policies(
        auth: AuthContext = Depends(get_current_auth),
        service: GatewayService = Depends(get_service),
    ) -> list[PolicyOut]:
        return [PolicyOut(**asdict(item)) for item in service.list_policies(auth)]

    @app.get("/tool-registry", response_model=list[ToolManifestOut])
    def list_tool_registry(
        auth: AuthContext = Depends(get_current_auth),
        service: GatewayService = Depends(get_service),
    ) -> list[ToolManifestOut]:
        return [ToolManifestOut(**public_manifest(item)) for item in service.list_tools(auth)]

    @app.post(
        "/tool-registry/{tool_id}/verify",
        response_model=ManifestVerificationOut,
    )
    def verify_tool_manifest(
        tool_id: str,
        payload: ManifestCandidateIn,
        auth: AuthContext = Depends(get_current_auth),
        service: GatewayService = Depends(get_service),
    ) -> ManifestVerificationOut:
        try:
            result = service.verify_manifest(
                auth,
                tool_id,
                payload.model_dump(exclude={"enforce_quarantine"}),
                enforce_quarantine=payload.enforce_quarantine,
            )
        except (PermissionError, ValueError) as exc:
            _raise_service_error(exc)
        return ManifestVerificationOut(**result)

    @app.post("/tool-registry/{tool_id}/restore", response_model=ToolManifestOut)
    def restore_tool_manifest(
        tool_id: str,
        auth: AuthContext = Depends(get_current_auth),
        service: GatewayService = Depends(get_service),
    ) -> ToolManifestOut:
        try:
            manifest = service.restore_manifest(auth, tool_id)
        except (PermissionError, ValueError) as exc:
            _raise_service_error(exc)
        return ToolManifestOut(**public_manifest(manifest))

    @app.get("/requests", response_model=list[RequestOut])
    def list_requests(
        auth: AuthContext = Depends(get_current_auth),
        service: GatewayService = Depends(get_service),
    ) -> list[RequestOut]:
        return [RequestOut(**asdict(item)) for item in service.list_requests(auth)]

    @app.get("/requests/{request_id}", response_model=RequestOut)
    def get_request(
        request_id: str,
        auth: AuthContext = Depends(get_current_auth),
        service: GatewayService = Depends(get_service),
    ) -> RequestOut:
        try:
            gateway_request = service.get_request(auth, request_id)
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
        return RequestOut(**asdict(gateway_request))

    @app.post("/requests", response_model=RequestOut, status_code=status.HTTP_201_CREATED)
    def submit_request(
        payload: RequestIn,
        auth: AuthContext = Depends(get_current_auth),
        service: GatewayService = Depends(get_service),
    ) -> RequestOut:
        try:
            gateway_request = service.submit_request(auth, **payload.model_dump())
        except (PermissionError, ValueError) as exc:
            _raise_service_error(exc)
        return RequestOut(**asdict(gateway_request))

    @app.get("/approvals", response_model=list[ApprovalOut])
    def list_approvals(
        auth: AuthContext = Depends(get_current_auth),
        service: GatewayService = Depends(get_service),
    ) -> list[ApprovalOut]:
        return [ApprovalOut(**asdict(item)) for item in service.list_approvals(auth)]

    @app.post(
        "/approvals/{approval_id}/decision",
        response_model=ApprovalDecisionOut,
    )
    def decide_approval(
        approval_id: str,
        payload: ApprovalDecisionIn,
        auth: AuthContext = Depends(get_current_auth),
        service: GatewayService = Depends(get_service),
    ) -> ApprovalDecisionOut:
        try:
            approval, grant = service.decide_approval(auth, approval_id, payload.decision)
        except (PermissionError, ValueError) as exc:
            _raise_service_error(exc)
        return ApprovalDecisionOut(
            approval=ApprovalOut(**asdict(approval)),
            capability_lease=grant.token if grant else None,
            expires_at=grant.expires_at if grant else None,
        )

    @app.post("/requests/{request_id}/execute", response_model=ExecutionOut)
    def execute_approved_request(
        request_id: str,
        payload: ApprovedExecutionIn,
        auth: AuthContext = Depends(get_current_auth),
        service: GatewayService = Depends(get_service),
    ) -> ExecutionOut:
        try:
            execution = service.execute_with_lease(
                auth,
                request_id,
                payload.arguments,
                payload.capability_lease,
            )
        except (PermissionError, ValueError) as exc:
            _raise_service_error(exc)
        return ExecutionOut(**asdict(execution))

    @app.get("/requests/{request_id}/evidence", response_model=EvidenceOut)
    def request_evidence(
        request_id: str,
        auth: AuthContext = Depends(get_current_auth),
        service: GatewayService = Depends(get_service),
    ) -> EvidenceOut:
        try:
            evidence = service.evidence_pack(auth, request_id)
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
        return EvidenceOut(**evidence)

    @app.get("/incidents", response_model=list[IncidentOut])
    def list_incidents(
        auth: AuthContext = Depends(get_current_auth),
        service: GatewayService = Depends(get_service),
    ) -> list[IncidentOut]:
        return [IncidentOut(**asdict(item)) for item in service.list_incidents(auth)]

    @app.post("/attack-lab/run", response_model=AttackLabOut)
    def run_attack_lab(
        auth: AuthContext = Depends(get_current_auth),
        service: GatewayService = Depends(get_service),
    ) -> AttackLabOut:
        try:
            result = service.run_attack_lab(auth)
        except (PermissionError, ValueError) as exc:
            _raise_service_error(exc)
        return AttackLabOut(**result)

    @app.post("/mcp")
    def mcp_gateway(
        payload: MCPRequestIn,
        origin: str | None = Header(default=None),
        mcp_method: str | None = Header(default=None, alias="Mcp-Method"),
        mcp_name: str | None = Header(default=None, alias="Mcp-Name"),
        auth: AuthContext = Depends(get_current_auth),
        service: GatewayService = Depends(get_service),
    ) -> dict[str, Any]:
        if origin and origin.rstrip("/") not in allowed_origins():
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Origin is not allowlisted for MCP transport.",
            )
        if mcp_method and mcp_method != payload.method:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Mcp-Method header does not match the JSON-RPC method.",
            )
        if payload.method == "tools/call":
            body_name = payload.params.get("name")
            if mcp_name and mcp_name != body_name:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Mcp-Name header does not match the JSON-RPC tool name.",
                )

        if payload.method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": payload.id,
                "result": {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {"tools": {"listChanged": True}},
                    "serverInfo": {
                        "name": "mcp-security-gateway",
                        "version": "0.2.0",
                    },
                    "instructions": (
                        "All tool calls are manifest-pinned, policy evaluated, "
                        "approval-bound when required, and audit recorded."
                    ),
                },
            }
        if payload.method == "ping":
            return {"jsonrpc": "2.0", "id": payload.id, "result": {}}
        if payload.method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": payload.id,
                "result": {"tools": service.protocol_tools(auth)},
            }
        if payload.method != "tools/call":
            return {
                "jsonrpc": "2.0",
                "id": payload.id,
                "error": {"code": -32601, "message": "Method not found"},
            }

        name = payload.params.get("name")
        arguments = payload.params.get("arguments", {})
        metadata = payload.params.get("_meta", {})
        if not isinstance(name, str) or not isinstance(arguments, dict) or not isinstance(metadata, dict):
            return {
                "jsonrpc": "2.0",
                "id": payload.id,
                "error": {"code": -32602, "message": "Invalid tools/call parameters"},
            }

        request_id = metadata.get("gateway/requestId")
        lease = metadata.get("gateway/capabilityLease")
        try:
            if request_id or lease:
                if not isinstance(request_id, str) or not isinstance(lease, str):
                    raise ValueError("Both requestId and capabilityLease are required.")
                execution = service.execute_with_lease(auth, request_id, arguments, lease)
                return _mcp_tool_result(
                    payload.id,
                    status_value="executed",
                    message="Approved tool call executed through the controlled adapter.",
                    structured={
                        "requestId": execution.request_id,
                        "executionId": execution.id,
                        "result": json_loads_safe(execution.result_json),
                        "resultDigest": execution.result_digest,
                    },
                )

            manifest = service.repo.get_tool_by_name(auth.user.organization_id, name)
            if not manifest:
                raise ValueError(f"Unknown MCP tool '{name}'.")
            gateway_request = service.submit_request(
                auth,
                mcp_server_id=manifest.mcp_server_id,
                tool_name=name,
                requested_scope=manifest.required_scope,
                justification=str(
                    metadata.get(
                        "gateway/justification",
                        f"Execute MCP tool call for {name} through the governed gateway.",
                    )
                ),
                estimated_tokens=int(metadata.get("gateway/estimatedTokens", 500)),
                arguments=arguments,
            )
            if gateway_request.status == "approved":
                execution = service.execute_allowed_request(auth, gateway_request.id, arguments)
                return _mcp_tool_result(
                    payload.id,
                    status_value="executed",
                    message="Low-risk verified tool call executed.",
                    structured={
                        "requestId": gateway_request.id,
                        "executionId": execution.id,
                        "result": json_loads_safe(execution.result_json),
                        "resultDigest": execution.result_digest,
                    },
                )
            if gateway_request.status == "awaiting_approval":
                return _mcp_tool_result(
                    payload.id,
                    status_value="approval_required",
                    message="Tool call is held for maker-checker approval.",
                    structured={
                        "requestId": gateway_request.id,
                        "requestDigest": gateway_request.request_digest,
                        "policyVersion": gateway_request.policy_version,
                    },
                )
            return _mcp_tool_result(
                payload.id,
                status_value="denied",
                message="Tool call was blocked before execution.",
                structured={
                    "requestId": gateway_request.id,
                    "reason": gateway_request.risk_reason,
                    "policyVersion": gateway_request.policy_version,
                },
                is_error=True,
            )
        except (PermissionError, ValueError) as exc:
            return _mcp_tool_result(
                payload.id,
                status_value="denied",
                message="Gateway rejected the tool call.",
                structured={"reason": str(exc)},
                is_error=True,
            )

    return app


def json_loads_safe(value: str) -> Any:
    try:
        return __import__("json").loads(value)
    except (TypeError, ValueError):
        return {"status": "unavailable"}


app = create_app()
