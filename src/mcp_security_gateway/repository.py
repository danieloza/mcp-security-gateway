from __future__ import annotations

import sqlite3
from pathlib import Path

from mcp_security_gateway.config import database_url
from mcp_security_gateway.models import Approval, GatewayRequest, Incident, MCPServer, Policy, User
from mcp_security_gateway.seed_data import MCP_SERVERS, POLICIES, USERS


class SQLiteRepository:
    def __init__(self, url: str | None = None) -> None:
        self.url = url or database_url()
        self.path = self._resolve_path(self.url)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    @staticmethod
    def _resolve_path(url: str) -> Path:
        if not url.startswith("sqlite:///"):
            raise ValueError("Only sqlite URLs are supported in this MVP.")
        return Path(url.removeprefix("sqlite:///"))

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                create table if not exists users (
                    id text primary key,
                    name text not null,
                    role text not null,
                    organization_id text not null,
                    api_key text not null unique
                );
                create table if not exists mcp_servers (
                    id text primary key,
                    name text not null,
                    environment text not null,
                    sensitivity text not null,
                    allowed_scopes text not null
                );
                create table if not exists policies (
                    id text primary key,
                    name text not null,
                    mode text not null,
                    description text not null
                );
                create table if not exists gateway_requests (
                    id text primary key,
                    organization_id text not null,
                    requested_by text not null,
                    mcp_server_id text not null,
                    tool_name text not null,
                    requested_scope text not null,
                    justification text not null,
                    estimated_tokens integer not null,
                    status text not null,
                    policy_id text not null,
                    risk_reason text not null,
                    redacted_arguments text not null
                );
                create table if not exists approvals (
                    id text primary key,
                    request_id text not null,
                    organization_id text not null,
                    status text not null,
                    reason text not null,
                    decided_by text
                );
                create table if not exists incidents (
                    id text primary key,
                    request_id text not null,
                    organization_id text not null,
                    severity text not null,
                    summary text not null
                );
                """
            )
            connection.executemany("insert or ignore into users values (?, ?, ?, ?, ?)", USERS)
            connection.executemany("insert or ignore into mcp_servers values (?, ?, ?, ?, ?)", MCP_SERVERS)
            connection.executemany("insert or ignore into policies values (?, ?, ?, ?)", POLICIES)

    def _fetch_one(self, query: str, params: tuple[object, ...]) -> sqlite3.Row | None:
        with self._connect() as connection:
            return connection.execute(query, params).fetchone()

    def _fetch_all(self, query: str, params: tuple[object, ...] = ()) -> list[sqlite3.Row]:
        with self._connect() as connection:
            return connection.execute(query, params).fetchall()

    @staticmethod
    def _user(row: sqlite3.Row) -> User:
        return User(**dict(row))

    @staticmethod
    def _server(row: sqlite3.Row) -> MCPServer:
        return MCPServer(**dict(row))

    @staticmethod
    def _policy(row: sqlite3.Row) -> Policy:
        return Policy(**dict(row))

    @staticmethod
    def _request(row: sqlite3.Row) -> GatewayRequest:
        return GatewayRequest(**dict(row))

    @staticmethod
    def _approval(row: sqlite3.Row) -> Approval:
        return Approval(**dict(row))

    @staticmethod
    def _incident(row: sqlite3.Row) -> Incident:
        return Incident(**dict(row))

    def get_user_by_api_key(self, api_key: str) -> User | None:
        row = self._fetch_one("select * from users where api_key = ?", (api_key,))
        return self._user(row) if row else None

    def list_servers(self) -> list[MCPServer]:
        return [self._server(row) for row in self._fetch_all("select * from mcp_servers order by id")]

    def get_server(self, server_id: str) -> MCPServer | None:
        row = self._fetch_one("select * from mcp_servers where id = ?", (server_id,))
        return self._server(row) if row else None

    def list_policies(self) -> list[Policy]:
        return [self._policy(row) for row in self._fetch_all("select * from policies order by id")]

    def list_requests(self, organization_id: str) -> list[GatewayRequest]:
        rows = self._fetch_all(
            "select * from gateway_requests where organization_id = ? order by id desc", (organization_id,)
        )
        return [self._request(row) for row in rows]

    def get_request(self, request_id: str) -> GatewayRequest | None:
        row = self._fetch_one("select * from gateway_requests where id = ?", (request_id,))
        return self._request(row) if row else None

    def save_request(self, request: GatewayRequest) -> GatewayRequest:
        with self._connect() as connection:
            connection.execute(
                """
                insert into gateway_requests (
                    id, organization_id, requested_by, mcp_server_id, tool_name, requested_scope,
                    justification, estimated_tokens, status, policy_id, risk_reason, redacted_arguments
                ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    request.id,
                    request.organization_id,
                    request.requested_by,
                    request.mcp_server_id,
                    request.tool_name,
                    request.requested_scope,
                    request.justification,
                    request.estimated_tokens,
                    request.status,
                    request.policy_id,
                    request.risk_reason,
                    request.redacted_arguments,
                ),
            )
        return request

    def update_request_status(self, request_id: str, status: str) -> GatewayRequest:
        with self._connect() as connection:
            connection.execute("update gateway_requests set status = ? where id = ?", (status, request_id))
        request = self.get_request(request_id)
        if not request:
            raise ValueError(f"Unknown request '{request_id}'.")
        return request

    def save_approval(self, approval: Approval) -> Approval:
        with self._connect() as connection:
            connection.execute(
                "insert into approvals (id, request_id, organization_id, status, reason, decided_by) values (?, ?, ?, ?, ?, ?)",
                (approval.id, approval.request_id, approval.organization_id, approval.status, approval.reason, approval.decided_by),
            )
        return approval

    def list_approvals(self, organization_id: str) -> list[Approval]:
        rows = self._fetch_all("select * from approvals where organization_id = ? order by id desc", (organization_id,))
        return [self._approval(row) for row in rows]

    def get_approval(self, approval_id: str) -> Approval | None:
        row = self._fetch_one("select * from approvals where id = ?", (approval_id,))
        return self._approval(row) if row else None

    def update_approval(self, approval_id: str, status: str, decided_by: str) -> Approval:
        with self._connect() as connection:
            connection.execute(
                "update approvals set status = ?, decided_by = ? where id = ?",
                (status, decided_by, approval_id),
            )
        approval = self.get_approval(approval_id)
        if not approval:
            raise ValueError(f"Unknown approval '{approval_id}'.")
        return approval

    def save_incident(self, incident: Incident) -> Incident:
        with self._connect() as connection:
            connection.execute(
                "insert into incidents (id, request_id, organization_id, severity, summary) values (?, ?, ?, ?, ?)",
                (incident.id, incident.request_id, incident.organization_id, incident.severity, incident.summary),
            )
        return incident

    def list_incidents(self, organization_id: str) -> list[Incident]:
        rows = self._fetch_all("select * from incidents where organization_id = ? order by id desc", (organization_id,))
        return [self._incident(row) for row in rows]

    def health_counts(self) -> dict[str, int]:
        with self._connect() as connection:
            return {
                "users": connection.execute("select count(*) from users").fetchone()[0],
                "servers": connection.execute("select count(*) from mcp_servers").fetchone()[0],
                "requests": connection.execute("select count(*) from gateway_requests").fetchone()[0],
                "approvals": connection.execute("select count(*) from approvals where status = 'pending'").fetchone()[0],
                "incidents": connection.execute("select count(*) from incidents").fetchone()[0],
            }


repository = SQLiteRepository()
