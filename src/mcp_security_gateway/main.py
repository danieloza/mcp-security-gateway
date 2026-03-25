from __future__ import annotations

from dataclasses import asdict
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException, status
from fastapi.responses import FileResponse

from mcp_security_gateway.config import redis_url
from mcp_security_gateway.repository import SQLiteRepository, repository
from mcp_security_gateway.schemas import (
    ApprovalDecisionIn,
    ApprovalOut,
    HealthOut,
    IncidentOut,
    MCPServerOut,
    PolicyOut,
    RequestIn,
    RequestOut,
    UserOut,
)
from mcp_security_gateway.services import AuthContext, GatewayService
from mcp_security_gateway.state import RateLimitStore, build_rate_limit_store


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
    x_api_key: str | None = Header(default=None),
    service: GatewayService = Depends(get_service),
) -> AuthContext:
    if not x_api_key:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing X-API-Key header.")
    auth = service.build_auth_context(x_api_key)
    if not auth:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key.")
    return auth


def create_app(repo: SQLiteRepository | None = None, rates: RateLimitStore | None = None) -> FastAPI:
    app = FastAPI(title="MCP Security Gateway", version="0.1.0")
    dashboard_path = Path(__file__).with_name("dashboard.html")

    if repo is not None:
        app.dependency_overrides[get_repository] = lambda: repo
    if rates is not None:
        app.dependency_overrides[get_rate_limit_store] = lambda: rates

    @app.get("/", include_in_schema=False)
    def root() -> FileResponse:
        return FileResponse(dashboard_path)

    @app.get("/dashboard", include_in_schema=False)
    def dashboard() -> FileResponse:
        return FileResponse(dashboard_path)

    @app.get("/health", response_model=HealthOut)
    def health(service: GatewayService = Depends(get_service)) -> HealthOut:
        return HealthOut(**service.health_snapshot())

    @app.get("/me", response_model=UserOut)
    def me(auth: AuthContext = Depends(get_current_auth)) -> UserOut:
        payload = asdict(auth.user)
        payload.pop("api_key", None)
        return UserOut(**payload)

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
            request = service.get_request(auth, request_id)
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
        return RequestOut(**asdict(request))

    @app.post("/requests", response_model=RequestOut, status_code=status.HTTP_201_CREATED)
    def submit_request(
        payload: RequestIn,
        auth: AuthContext = Depends(get_current_auth),
        service: GatewayService = Depends(get_service),
    ) -> RequestOut:
        try:
            request = service.submit_request(auth, **payload.model_dump())
        except PermissionError as exc:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        return RequestOut(**asdict(request))

    @app.get("/approvals", response_model=list[ApprovalOut])
    def list_approvals(
        auth: AuthContext = Depends(get_current_auth),
        service: GatewayService = Depends(get_service),
    ) -> list[ApprovalOut]:
        return [ApprovalOut(**asdict(item)) for item in service.list_approvals(auth)]

    @app.post("/approvals/{approval_id}/decision", response_model=ApprovalOut)
    def decide_approval(
        approval_id: str,
        payload: ApprovalDecisionIn,
        auth: AuthContext = Depends(get_current_auth),
        service: GatewayService = Depends(get_service),
    ) -> ApprovalOut:
        try:
            approval = service.decide_approval(auth, approval_id, payload.decision)
        except PermissionError as exc:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        return ApprovalOut(**asdict(approval))

    @app.get("/incidents", response_model=list[IncidentOut])
    def list_incidents(
        auth: AuthContext = Depends(get_current_auth),
        service: GatewayService = Depends(get_service),
    ) -> list[IncidentOut]:
        return [IncidentOut(**asdict(item)) for item in service.list_incidents(auth)]

    return app


app = create_app()
