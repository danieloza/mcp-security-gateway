from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, Response, status
from fastapi.responses import FileResponse, JSONResponse
from starlette.concurrency import run_in_threadpool
from starlette.middleware.trustedhost import TrustedHostMiddleware

from mcp_security_gateway import __version__
from mcp_security_gateway.config import (
    allowed_hosts,
    allowed_origins,
    auth_mode,
    is_production,
    is_sandbox,
    max_request_bytes,
    redis_url,
)
from mcp_security_gateway.oauth import (
    CONSOLE_SCOPE,
    MCP_SCOPE,
    OAuthSettings,
    SigningKeysUnavailable,
    TokenRejected,
    TokenVerifier,
    challenge,
    load_oauth_settings,
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
    LeaseClaimOut,
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
from mcp_security_gateway.sandbox import BODY_METHODS, Sandbox, SandboxSettings
from mcp_security_gateway.services import AuthContext, GatewayService
from mcp_security_gateway.upstream import UpstreamRegistry, load_upstreams
from mcp_security_gateway.state import RateLimitStore, build_rate_limit_store
from mcp_security_gateway.tool_registry import public_manifest
from mcp_security_gateway.tool_names import NAME_STYLES


rate_limit_store = build_rate_limit_store(redis_url())

# Streamable HTTP revisions without JSON-RPC batching. 2025-03-26 is omitted on purpose:
# it requires servers to accept batches, which this gateway rejects.
SUPPORTED_PROTOCOL_VERSIONS = ("2025-11-25", "2025-06-18")


def negotiate_protocol_version(requested: object) -> str:
    """Echo the client's version when supported, otherwise offer the latest one."""
    if isinstance(requested, str) and requested in SUPPORTED_PROTOCOL_VERSIONS:
        return requested
    return SUPPORTED_PROTOCOL_VERSIONS[0]


def get_repository() -> SQLiteRepository:
    return repository


def get_rate_limit_store() -> RateLimitStore:
    return rate_limit_store


def get_service(
    request: Request,
    repo: SQLiteRepository = Depends(get_repository),
    rates: RateLimitStore = Depends(get_rate_limit_store),
) -> GatewayService:
    return GatewayService(repo, rates, upstreams=getattr(request.app.state, "upstreams", None))


@dataclass(frozen=True, slots=True)
class OAuthRuntime:
    settings: OAuthSettings
    verifier: TokenVerifier


def _static_auth(
    authorization: str | None,
    x_api_key: str | None,
    service: GatewayService,
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


def _oauth_auth(
    oauth: OAuthRuntime,
    authorization: str | None,
    x_api_key: str | None,
    service: GatewayService,
    scope: str,
) -> AuthContext:
    """Validate an access token for this resource and map it to a gateway user.

    Details never echo the token or its claims. The token itself goes no further
    than this function: the request continues with the mapped user only.
    """

    def unauthorized(detail: str, error: str | None = None) -> HTTPException:
        return HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=detail,
            headers={"WWW-Authenticate": challenge(oauth.settings, scope, error)},
        )

    scheme, _, token = (authorization or "").partition(" ")
    if not authorization or x_api_key is not None:
        # Static keys, X-API-Key included, are not credentials in this mode.
        raise unauthorized("An OAuth access token is required.")
    if scheme.lower() != "bearer" or not token:
        raise unauthorized("Authorization must use the Bearer scheme.", "invalid_request")
    try:
        verified = oauth.verifier.verify(token)
    except SigningKeysUnavailable as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Access tokens cannot be verified right now.",
        ) from exc
    except TokenRejected as exc:
        raise unauthorized("The access token is invalid for this resource.", "invalid_token") from exc
    if scope not in verified.scopes:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"The access token lacks the {scope} scope.",
            headers={"WWW-Authenticate": challenge(oauth.settings, scope, "insufficient_scope")},
        )
    user_id = oauth.settings.subjects.get(verified.subject)
    user = service.repo.get_user(user_id) if user_id else None
    if user is None:
        # A valid token for someone the gateway does not know: refused, never provisioned.
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="The token's subject is not a gateway user.",
        )
    return AuthContext(user)


def _authenticate(
    request: Request,
    authorization: str | None,
    x_api_key: str | None,
    service: GatewayService,
    scope: str,
) -> AuthContext:
    oauth: OAuthRuntime | None = getattr(request.app.state, "oauth", None)
    if oauth is None:
        return _static_auth(authorization, x_api_key, service)
    return _oauth_auth(oauth, authorization, x_api_key, service, scope)


def get_current_auth(
    request: Request,
    authorization: str | None = Header(default=None),
    x_api_key: str | None = Header(default=None),
    service: GatewayService = Depends(get_service),
) -> AuthContext:
    """The operator API. In OAuth mode it needs the `gateway:console` scope."""
    return _authenticate(request, authorization, x_api_key, service, CONSOLE_SCOPE)


def get_mcp_auth(
    request: Request,
    authorization: str | None = Header(default=None),
    x_api_key: str | None = Header(default=None),
    service: GatewayService = Depends(get_service),
) -> AuthContext:
    """The MCP endpoint. In OAuth mode it needs the `mcp:tools` scope."""
    return _authenticate(request, authorization, x_api_key, service, MCP_SCOPE)


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


def forwarded_for_and_peer(request: Request) -> tuple[str | None, str | None]:
    """Every X-Forwarded-For line, in order, and the TCP peer.

    A client can send its own X-Forwarded-For line before the one a proxy
    appends, so every line counts, not only the first.
    """
    forwarded_for = ", ".join(request.headers.getlist("x-forwarded-for")) or None
    return forwarded_for, request.client.host if request.client else None


def build_sandbox(
    repo: SQLiteRepository,
    rates: RateLimitStore,
    registry: UpstreamRegistry,
    **options: Any,
) -> Sandbox:
    """The public sandbox's guard. A reset reseeds the database and re-registers upstreams."""
    return Sandbox(
        SandboxSettings.from_environment(),
        repo,
        on_reset=lambda: GatewayService(repo, rates, upstreams=registry).register_upstreams(),
        **options,
    )


def create_app(
    repo: SQLiteRepository | None = None,
    rates: RateLimitStore | None = None,
    token_verifier: TokenVerifier | None = None,
    upstreams: UpstreamRegistry | None = None,
    sandbox: Sandbox | None = None,
) -> FastAPI:
    # Read first: production refuses to start with the public static keys.
    mode = auth_mode()
    oauth: OAuthRuntime | None = None
    if mode == "oauth":
        settings = token_verifier.settings if token_verifier else load_oauth_settings()
        oauth = OAuthRuntime(settings, token_verifier or TokenVerifier(settings))
    docs_url = None if is_production() else "/docs"
    openapi_url = None if is_production() else "/openapi.json"
    app = FastAPI(
        title="MCP Security Gateway",
        version=__version__,
        docs_url=docs_url,
        redoc_url=None,
        openapi_url=openapi_url,
    )
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=allowed_hosts())
    app.state.oauth = oauth
    # Upstream MCP servers come from configuration only; an agent never names one.
    registry = upstreams if upstreams is not None else UpstreamRegistry.from_configs(load_upstreams())
    app.state.upstreams = registry
    if registry:
        GatewayService(repo or repository, rates or rate_limit_store, upstreams=registry).register_upstreams()
    if sandbox is None and is_sandbox():
        sandbox = build_sandbox(repo or repository, rates or rate_limit_store, registry)
    app.state.sandbox = sandbox
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
        if sandbox is not None:
            if request.method in BODY_METHODS and "content-length" not in request.headers:
                return JSONResponse(
                    status_code=status.HTTP_411_LENGTH_REQUIRED,
                    content={"detail": "The sandbox needs a Content-Length header on request bodies."},
                )
            wait = sandbox.admit(*forwarded_for_and_peer(request))
            if wait is not None:
                return JSONResponse(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    content={"detail": "Sandbox request limit reached for this address."},
                    headers={"Retry-After": str(wait)},
                )
            await run_in_threadpool(sandbox.reset_if_due)
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
        return HealthOut(**service.health_snapshot(), auth_mode=mode)

    if sandbox is not None:
        guard = sandbox

        def require_sandbox_admin(auth: AuthContext) -> None:
            if auth.user.role not in {"security_admin", "platform_admin"}:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Only security or platform admins can change the sandbox.",
                )

        @app.get("/sandbox")
        def sandbox_status(request: Request) -> dict[str, Any]:
            return {**guard.status(), **guard.caller(*forwarded_for_and_peer(request))}

        @app.post("/sandbox/rug-pull")
        def sandbox_rug_pull(auth: AuthContext = Depends(get_current_auth)) -> dict[str, Any]:
            require_sandbox_admin(auth)
            try:
                guard.rug_pull()
            except OSError as exc:
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail="The sandbox test server did not answer.",
                ) from exc
            return {"status": "swapped"}

        @app.post("/sandbox/reset")
        def sandbox_reset(auth: AuthContext = Depends(get_current_auth)) -> dict[str, Any]:
            require_sandbox_admin(auth)
            wait = guard.manual_reset()
            if wait is not None:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="The sandbox was reset less than a minute ago.",
                    headers={"Retry-After": str(wait)},
                )
            return guard.status()

    if oauth is not None:
        metadata = oauth.settings.metadata_document()

        # RFC 9728 protected-resource metadata, at the path-inserted URI only:
        # a document at the root would have to describe the origin, not /mcp.
        @app.get(oauth.settings.metadata_path, include_in_schema=False)
        def protected_resource_metadata() -> JSONResponse:
            return JSONResponse(metadata)

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

    @app.get("/upstreams")
    def list_upstreams(
        auth: AuthContext = Depends(get_current_auth),
        service: GatewayService = Depends(get_service),
    ) -> list[dict[str, Any]]:
        return service.list_upstreams(auth)

    @app.post("/upstreams/{server_id}/sync")
    def sync_upstream(
        server_id: str,
        auth: AuthContext = Depends(get_current_auth),
        service: GatewayService = Depends(get_service),
    ) -> dict[str, Any]:
        try:
            return service.sync_upstream(auth, server_id)
        except (PermissionError, ValueError) as exc:
            _raise_service_error(exc)
        raise AssertionError("unreachable")

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
            approval = service.decide_approval(auth, approval_id, payload.decision)
        except (PermissionError, ValueError) as exc:
            _raise_service_error(exc)
        return ApprovalDecisionOut(approval=ApprovalOut(**asdict(approval)))

    @app.post("/requests/{request_id}/lease", response_model=LeaseClaimOut)
    def claim_capability_lease(
        request_id: str,
        auth: AuthContext = Depends(get_current_auth),
        service: GatewayService = Depends(get_service),
    ) -> LeaseClaimOut:
        try:
            grant = service.claim_lease(auth, request_id)
        except (PermissionError, ValueError) as exc:
            _raise_service_error(exc)
        return LeaseClaimOut(
            request_id=request_id,
            capability_lease=grant.token,
            expires_at=grant.expires_at,
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

    @app.post("/mcp", response_model=None)
    def mcp_gateway(
        payload: MCPRequestIn,
        origin: str | None = Header(default=None),
        mcp_method: str | None = Header(default=None, alias="Mcp-Method"),
        mcp_name: str | None = Header(default=None, alias="Mcp-Name"),
        protocol_version: str | None = Header(default=None, alias="MCP-Protocol-Version"),
        tool_names: str = Query(default="dotted"),
        auth: AuthContext = Depends(get_mcp_auth),
        service: GatewayService = Depends(get_service),
    ) -> dict[str, Any] | Response:
        if tool_names not in NAME_STYLES:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"tool_names must be one of: {', '.join(NAME_STYLES)}.",
            )
        if origin and origin.rstrip("/") not in allowed_origins():
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Origin is not allowlisted for MCP transport.",
            )
        if protocol_version and protocol_version not in SUPPORTED_PROTOCOL_VERSIONS:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unsupported MCP-Protocol-Version; supported: {', '.join(SUPPORTED_PROTOCOL_VERSIONS)}.",
            )
        if "id" not in payload.model_fields_set:
            # A message without an id is a notification: accept it without a JSON-RPC response.
            if payload.method.startswith("notifications/"):
                return Response(status_code=status.HTTP_202_ACCEPTED)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="JSON-RPC requests must include an id; only notifications may omit it.",
            )
        if payload.id is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="MCP request ids must be a string or an integer, not null.",
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
                    "protocolVersion": negotiate_protocol_version(payload.params.get("protocolVersion")),
                    # No server-to-client stream exists (GET /mcp is 405), so list changes are never announced.
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {
                        "name": "mcp-security-gateway",
                        "version": __version__,
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
                "result": {"tools": service.protocol_tools(auth, tool_names)},
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
                return _execution_result(
                    payload.id, execution, "Approved tool call executed through the controlled adapter."
                )

            # Policy, approvals and the audit trail see only the canonical name.
            name = service.canonical_tool_name(auth, name)
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
                return _execution_result(payload.id, execution, "Low-risk verified tool call executed.")
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


def _execution_result(request_id: str | int | None, execution: Any, message: str) -> dict[str, Any]:
    result = json_loads_safe(execution.result_json)
    structured = {
        "requestId": execution.request_id,
        "executionId": execution.id,
        "resultDigest": execution.result_digest,
    }
    if isinstance(result, dict) and result.get("withheld"):
        # The upstream ran, but its output looked like instructions to the agent:
        # the agent gets the finding types and a digest, never the text.
        return _mcp_tool_result(
            request_id,
            status_value="response_blocked",
            message="The tool ran, but its output was withheld: it looked like instructions to the agent.",
            structured={**structured, "findings": result.get("findings", []), "contentDigest": result.get("content_digest")},
            is_error=True,
        )
    return _mcp_tool_result(request_id, status_value="executed", message=message, structured={**structured, "result": result})


def json_loads_safe(value: str) -> Any:
    try:
        return __import__("json").loads(value)
    except (TypeError, ValueError):
        return {"status": "unavailable"}


app = create_app()
