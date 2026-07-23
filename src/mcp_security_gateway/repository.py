from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

from mcp_security_gateway.config import database_url
from mcp_security_gateway.models import (
    Approval,
    AuditEvent,
    CapabilityLease,
    ExecutionRecord,
    GatewayRequest,
    Incident,
    MCPServer,
    Policy,
    ToolManifest,
    User,
)
from mcp_security_gateway.security import (
    audit_event_digest,
    canonical_json,
    hash_secret,
    new_id,
    parse_utc,
    utc_now,
    utc_now_iso,
)
from mcp_security_gateway.seed_data import MCP_SERVERS, POLICIES, TOOL_DEFINITIONS, USERS
from mcp_security_gateway.tool_registry import compute_manifest_digest, manifest_payload


class SQLiteRepository:
    def __init__(self, url: str | None = None) -> None:
        self.url = url or database_url()
        self.path = self._resolve_path(self.url)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    @staticmethod
    def _resolve_path(url: str) -> Path:
        if not url.startswith("sqlite:///"):
            raise ValueError("Only sqlite URLs are supported by the portfolio runtime.")
        return Path(url.removeprefix("sqlite:///"))

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("pragma foreign_keys = on")
        connection.execute("pragma busy_timeout = 10000")
        return connection

    @staticmethod
    def _table_columns(connection: sqlite3.Connection, table: str) -> set[str]:
        return {str(row["name"]) for row in connection.execute(f"pragma table_info({table})")}

    @staticmethod
    def _ensure_column(
        connection: sqlite3.Connection,
        table: str,
        name: str,
        declaration: str,
    ) -> None:
        if name not in SQLiteRepository._table_columns(connection, table):
            connection.execute(f"alter table {table} add column {name} {declaration}")

    def _migrate_plaintext_api_keys(self, connection: sqlite3.Connection) -> None:
        columns = self._table_columns(connection, "users")
        if not columns or "api_key" not in columns:
            return

        legacy_rows = connection.execute(
            "select id, name, role, organization_id, api_key from users"
        ).fetchall()
        connection.execute("alter table users rename to users_legacy_plaintext")
        connection.execute(
            """
            create table users (
                id text primary key,
                name text not null,
                role text not null,
                organization_id text not null,
                api_key_hash text not null unique
            )
            """
        )
        connection.executemany(
            """
            insert into users (id, name, role, organization_id, api_key_hash)
            values (?, ?, ?, ?, ?)
            """,
            [
                (
                    row["id"],
                    row["name"],
                    row["role"],
                    row["organization_id"],
                    hash_secret(row["api_key"]),
                )
                for row in legacy_rows
            ],
        )
        connection.execute("drop table users_legacy_plaintext")

    def _initialize(self) -> None:
        with self._connect() as connection:
            self._migrate_plaintext_api_keys(connection)
            connection.executescript(
                """
                create table if not exists users (
                    id text primary key,
                    name text not null,
                    role text not null,
                    organization_id text not null,
                    api_key_hash text not null unique
                );
                create table if not exists mcp_servers (
                    id text primary key,
                    organization_id text not null,
                    name text not null,
                    environment text not null,
                    sensitivity text not null,
                    allowed_scopes text not null,
                    trust_status text not null
                );
                create table if not exists policies (
                    id text primary key,
                    organization_id text not null,
                    name text not null,
                    mode text not null,
                    description text not null,
                    version text not null
                );
                create table if not exists tool_manifests (
                    id text primary key,
                    organization_id text not null,
                    mcp_server_id text not null,
                    name text not null,
                    description text not null,
                    required_scope text not null,
                    risk_level text not null,
                    input_schema text not null,
                    annotations text not null,
                    manifest_digest text not null,
                    trust_status text not null,
                    verified_at text not null,
                    unique (organization_id, name)
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
                    policy_version text not null,
                    risk_reason text not null,
                    policy_trace text not null,
                    redacted_arguments text not null,
                    arguments_digest text not null,
                    manifest_digest text not null,
                    request_digest text not null,
                    execution_status text not null,
                    created_at text not null,
                    updated_at text not null
                );
                create table if not exists approvals (
                    id text primary key,
                    request_id text not null,
                    organization_id text not null,
                    status text not null,
                    reason text not null,
                    request_digest text not null,
                    requested_by text not null,
                    decided_by text,
                    created_at text not null,
                    decided_at text
                );
                create table if not exists capability_leases (
                    id text primary key,
                    request_id text not null,
                    organization_id text not null,
                    token_hash text not null unique,
                    request_digest text not null,
                    issued_by text not null,
                    expires_at text not null,
                    used_at text,
                    created_at text not null
                );
                create table if not exists incidents (
                    id text primary key,
                    request_id text not null,
                    organization_id text not null,
                    severity text not null,
                    summary text not null,
                    created_at text not null
                );
                create table if not exists executions (
                    id text primary key,
                    request_id text not null,
                    organization_id text not null,
                    tool_name text not null,
                    status text not null,
                    result_json text not null,
                    result_digest text not null,
                    latency_ms integer not null,
                    created_at text not null
                );
                create table if not exists audit_events (
                    id text primary key,
                    organization_id text not null,
                    event_type text not null,
                    subject_id text not null,
                    actor_id text not null,
                    payload_json text not null,
                    previous_digest text not null,
                    event_digest text not null,
                    created_at text not null
                );
                """
            )
            self._migrate_legacy_columns(connection)
            connection.executescript(
                """
                create index if not exists idx_requests_org_created
                    on gateway_requests (organization_id, created_at desc);
                create index if not exists idx_approvals_org_status
                    on approvals (organization_id, status);
                create index if not exists idx_audit_org_created
                    on audit_events (organization_id, created_at);
                """
            )
            self._seed(connection)

    def _migrate_legacy_columns(self, connection: sqlite3.Connection) -> None:
        migrations = {
            "mcp_servers": {
                "organization_id": "text not null default 'org_danex'",
                "trust_status": "text not null default 'verified'",
            },
            "policies": {
                "organization_id": "text not null default 'org_danex'",
                "version": "text not null default '2026.07.24-default'",
            },
            "gateway_requests": {
                "policy_version": "text not null default 'legacy'",
                "policy_trace": "text not null default '[]'",
                "arguments_digest": "text not null default ''",
                "manifest_digest": "text not null default ''",
                "request_digest": "text not null default ''",
                "execution_status": "text not null default 'not_executed'",
                "created_at": "text not null default '1970-01-01T00:00:00Z'",
                "updated_at": "text not null default '1970-01-01T00:00:00Z'",
            },
            "approvals": {
                "request_digest": "text not null default ''",
                "requested_by": "text not null default 'legacy'",
                "created_at": "text not null default '1970-01-01T00:00:00Z'",
                "decided_at": "text",
            },
            "incidents": {
                "created_at": "text not null default '1970-01-01T00:00:00Z'",
            },
        }
        for table, columns in migrations.items():
            for name, declaration in columns.items():
                self._ensure_column(connection, table, name, declaration)

    def _seed(self, connection: sqlite3.Connection) -> None:
        connection.executemany(
            """
            insert or ignore into users (id, name, role, organization_id, api_key_hash)
            values (?, ?, ?, ?, ?)
            """,
            USERS,
        )
        connection.executemany(
            """
            insert or ignore into mcp_servers (
                id, organization_id, name, environment, sensitivity, allowed_scopes, trust_status
            ) values (?, ?, ?, ?, ?, ?, ?)
            """,
            MCP_SERVERS,
        )
        connection.executemany(
            """
            insert or ignore into policies (
                id, organization_id, name, mode, description, version
            ) values (?, ?, ?, ?, ?, ?)
            """,
            POLICIES,
        )
        for definition in TOOL_DEFINITIONS:
            payload = manifest_payload(
                mcp_server_id=definition["mcp_server_id"],
                name=definition["name"],
                description=definition["description"],
                required_scope=definition["required_scope"],
                risk_level=definition["risk_level"],
                input_schema=definition["input_schema"],
                annotations=definition["annotations"],
            )
            connection.execute(
                """
                insert into tool_manifests (
                    id, organization_id, mcp_server_id, name, description,
                    required_scope, risk_level, input_schema, annotations,
                    manifest_digest, trust_status, verified_at
                ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                on conflict(id) do update set
                    organization_id = excluded.organization_id,
                    mcp_server_id = excluded.mcp_server_id,
                    name = excluded.name,
                    description = excluded.description,
                    required_scope = excluded.required_scope,
                    risk_level = excluded.risk_level,
                    input_schema = excluded.input_schema,
                    annotations = excluded.annotations,
                    manifest_digest = excluded.manifest_digest,
                    verified_at = excluded.verified_at
                """,
                (
                    definition["id"],
                    definition["organization_id"],
                    definition["mcp_server_id"],
                    definition["name"],
                    definition["description"],
                    definition["required_scope"],
                    definition["risk_level"],
                    canonical_json(definition["input_schema"]),
                    canonical_json(definition["annotations"]),
                    compute_manifest_digest(payload),
                    "verified",
                    utc_now_iso(),
                ),
            )

    def _fetch_one(self, query: str, params: tuple[Any, ...]) -> sqlite3.Row | None:
        with self._connect() as connection:
            return connection.execute(query, params).fetchone()

    def _fetch_all(self, query: str, params: tuple[Any, ...] = ()) -> list[sqlite3.Row]:
        with self._connect() as connection:
            return connection.execute(query, params).fetchall()

    @staticmethod
    def _model(model: type[Any], row: sqlite3.Row) -> Any:
        return model(**dict(row))

    def get_user_by_api_key_hash(self, api_key_hash: str) -> User | None:
        row = self._fetch_one("select * from users where api_key_hash = ?", (api_key_hash,))
        return self._model(User, row) if row else None

    def list_servers(self, organization_id: str) -> list[MCPServer]:
        rows = self._fetch_all(
            "select * from mcp_servers where organization_id = ? order by id",
            (organization_id,),
        )
        return [self._model(MCPServer, row) for row in rows]

    def get_server(self, organization_id: str, server_id: str) -> MCPServer | None:
        row = self._fetch_one(
            "select * from mcp_servers where organization_id = ? and id = ?",
            (organization_id, server_id),
        )
        return self._model(MCPServer, row) if row else None

    def list_policies(self, organization_id: str) -> list[Policy]:
        rows = self._fetch_all(
            "select * from policies where organization_id = ? order by id",
            (organization_id,),
        )
        return [self._model(Policy, row) for row in rows]

    def get_policy(self, organization_id: str, policy_id: str) -> Policy:
        row = self._fetch_one(
            "select * from policies where organization_id = ? and id = ?",
            (organization_id, policy_id),
        )
        if not row:
            raise ValueError(f"Unknown policy '{policy_id}'.")
        return self._model(Policy, row)

    def list_tools(self, organization_id: str) -> list[ToolManifest]:
        rows = self._fetch_all(
            "select * from tool_manifests where organization_id = ? order by name",
            (organization_id,),
        )
        return [self._model(ToolManifest, row) for row in rows]

    def get_tool(self, organization_id: str, tool_id: str) -> ToolManifest | None:
        row = self._fetch_one(
            "select * from tool_manifests where organization_id = ? and id = ?",
            (organization_id, tool_id),
        )
        return self._model(ToolManifest, row) if row else None

    def get_tool_by_name(self, organization_id: str, name: str) -> ToolManifest | None:
        row = self._fetch_one(
            "select * from tool_manifests where organization_id = ? and name = ?",
            (organization_id, name),
        )
        return self._model(ToolManifest, row) if row else None

    def set_tool_trust(self, organization_id: str, tool_id: str, status: str) -> ToolManifest:
        with self._connect() as connection:
            cursor = connection.execute(
                """
                update tool_manifests
                set trust_status = ?, verified_at = ?
                where organization_id = ? and id = ?
                """,
                (status, utc_now_iso(), organization_id, tool_id),
            )
            if cursor.rowcount != 1:
                raise ValueError(f"Unknown tool manifest '{tool_id}'.")
        tool = self.get_tool(organization_id, tool_id)
        if not tool:
            raise ValueError(f"Unknown tool manifest '{tool_id}'.")
        return tool

    def list_requests(self, organization_id: str) -> list[GatewayRequest]:
        rows = self._fetch_all(
            "select * from gateway_requests where organization_id = ? order by created_at desc",
            (organization_id,),
        )
        return [self._model(GatewayRequest, row) for row in rows]

    def get_request(self, organization_id: str, request_id: str) -> GatewayRequest | None:
        row = self._fetch_one(
            "select * from gateway_requests where organization_id = ? and id = ?",
            (organization_id, request_id),
        )
        return self._model(GatewayRequest, row) if row else None

    def save_request(self, request: GatewayRequest) -> GatewayRequest:
        with self._connect() as connection:
            connection.execute(
                """
                insert into gateway_requests (
                    id, organization_id, requested_by, mcp_server_id, tool_name,
                    requested_scope, justification, estimated_tokens, status,
                    policy_id, policy_version, risk_reason, policy_trace,
                    redacted_arguments, arguments_digest, manifest_digest,
                    request_digest, execution_status, created_at, updated_at
                ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                tuple(request.__dict__.values()) if hasattr(request, "__dict__") else (
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
                    request.policy_version,
                    request.risk_reason,
                    request.policy_trace,
                    request.redacted_arguments,
                    request.arguments_digest,
                    request.manifest_digest,
                    request.request_digest,
                    request.execution_status,
                    request.created_at,
                    request.updated_at,
                ),
            )
        return request

    def update_request_status(
        self,
        organization_id: str,
        request_id: str,
        *,
        status: str,
        execution_status: str | None = None,
    ) -> GatewayRequest:
        updated_at = utc_now_iso()
        with self._connect() as connection:
            if execution_status is None:
                cursor = connection.execute(
                    """
                    update gateway_requests set status = ?, updated_at = ?
                    where organization_id = ? and id = ?
                    """,
                    (status, updated_at, organization_id, request_id),
                )
            else:
                cursor = connection.execute(
                    """
                    update gateway_requests
                    set status = ?, execution_status = ?, updated_at = ?
                    where organization_id = ? and id = ?
                    """,
                    (status, execution_status, updated_at, organization_id, request_id),
                )
            if cursor.rowcount != 1:
                raise ValueError(f"Unknown request '{request_id}'.")
        request = self.get_request(organization_id, request_id)
        if not request:
            raise ValueError(f"Unknown request '{request_id}'.")
        return request

    def save_approval(self, approval: Approval) -> Approval:
        with self._connect() as connection:
            connection.execute(
                """
                insert into approvals (
                    id, request_id, organization_id, status, reason, request_digest,
                    requested_by, decided_by, created_at, decided_at
                ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    approval.id,
                    approval.request_id,
                    approval.organization_id,
                    approval.status,
                    approval.reason,
                    approval.request_digest,
                    approval.requested_by,
                    approval.decided_by,
                    approval.created_at,
                    approval.decided_at,
                ),
            )
        return approval

    def list_approvals(self, organization_id: str) -> list[Approval]:
        rows = self._fetch_all(
            "select * from approvals where organization_id = ? order by created_at desc",
            (organization_id,),
        )
        return [self._model(Approval, row) for row in rows]

    def get_approval(self, organization_id: str, approval_id: str) -> Approval | None:
        row = self._fetch_one(
            "select * from approvals where organization_id = ? and id = ?",
            (organization_id, approval_id),
        )
        return self._model(Approval, row) if row else None

    def decide_pending_approval(
        self,
        organization_id: str,
        approval_id: str,
        decision: str,
        decided_by: str,
    ) -> Approval:
        decided_at = utc_now_iso()
        with self._connect() as connection:
            cursor = connection.execute(
                """
                update approvals
                set status = ?, decided_by = ?, decided_at = ?
                where organization_id = ? and id = ? and status = 'pending'
                """,
                (decision, decided_by, decided_at, organization_id, approval_id),
            )
            if cursor.rowcount != 1:
                raise ValueError("Approval is missing or has already been decided.")
        approval = self.get_approval(organization_id, approval_id)
        if not approval:
            raise ValueError(f"Unknown approval '{approval_id}'.")
        return approval

    def save_lease(self, lease: CapabilityLease) -> CapabilityLease:
        with self._connect() as connection:
            connection.execute(
                """
                insert into capability_leases (
                    id, request_id, organization_id, token_hash, request_digest,
                    issued_by, expires_at, used_at, created_at
                ) values (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    lease.id,
                    lease.request_id,
                    lease.organization_id,
                    lease.token_hash,
                    lease.request_digest,
                    lease.issued_by,
                    lease.expires_at,
                    lease.used_at,
                    lease.created_at,
                ),
            )
        return lease

    def consume_lease(
        self,
        *,
        organization_id: str,
        request_id: str,
        token_hash: str,
        request_digest: str,
    ) -> CapabilityLease:
        now = utc_now()
        used_at = now.isoformat().replace("+00:00", "Z")
        with self._connect() as connection:
            connection.execute("begin immediate")
            row = connection.execute(
                """
                select * from capability_leases
                where organization_id = ? and request_id = ? and token_hash = ?
                """,
                (organization_id, request_id, token_hash),
            ).fetchone()
            if not row:
                raise PermissionError("Invalid capability lease.")
            lease = self._model(CapabilityLease, row)
            if lease.request_digest != request_digest:
                raise PermissionError("Capability lease is not bound to this request.")
            if lease.used_at is not None:
                raise PermissionError("Capability lease has already been used.")
            if parse_utc(lease.expires_at) <= now:
                raise PermissionError("Capability lease has expired.")
            cursor = connection.execute(
                """
                update capability_leases set used_at = ?
                where id = ? and used_at is null
                """,
                (used_at, lease.id),
            )
            if cursor.rowcount != 1:
                raise PermissionError("Capability lease was consumed concurrently.")
        return CapabilityLease(
            id=lease.id,
            request_id=lease.request_id,
            organization_id=lease.organization_id,
            token_hash=lease.token_hash,
            request_digest=lease.request_digest,
            issued_by=lease.issued_by,
            expires_at=lease.expires_at,
            used_at=used_at,
            created_at=lease.created_at,
        )

    def save_incident(self, incident: Incident) -> Incident:
        with self._connect() as connection:
            connection.execute(
                """
                insert into incidents (
                    id, request_id, organization_id, severity, summary, created_at
                ) values (?, ?, ?, ?, ?, ?)
                """,
                (
                    incident.id,
                    incident.request_id,
                    incident.organization_id,
                    incident.severity,
                    incident.summary,
                    incident.created_at,
                ),
            )
        return incident

    def list_incidents(self, organization_id: str) -> list[Incident]:
        rows = self._fetch_all(
            "select * from incidents where organization_id = ? order by created_at desc",
            (organization_id,),
        )
        return [self._model(Incident, row) for row in rows]

    def save_execution(self, execution: ExecutionRecord) -> ExecutionRecord:
        with self._connect() as connection:
            connection.execute(
                """
                insert into executions (
                    id, request_id, organization_id, tool_name, status,
                    result_json, result_digest, latency_ms, created_at
                ) values (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    execution.id,
                    execution.request_id,
                    execution.organization_id,
                    execution.tool_name,
                    execution.status,
                    execution.result_json,
                    execution.result_digest,
                    execution.latency_ms,
                    execution.created_at,
                ),
            )
        return execution

    def list_executions(self, organization_id: str, request_id: str) -> list[ExecutionRecord]:
        rows = self._fetch_all(
            """
            select * from executions
            where organization_id = ? and request_id = ?
            order by created_at
            """,
            (organization_id, request_id),
        )
        return [self._model(ExecutionRecord, row) for row in rows]

    def save_audit_event(self, event: AuditEvent) -> AuditEvent:
        with self._connect() as connection:
            connection.execute(
                """
                insert into audit_events (
                    id, organization_id, event_type, subject_id, actor_id,
                    payload_json, previous_digest, event_digest, created_at
                ) values (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.id,
                    event.organization_id,
                    event.event_type,
                    event.subject_id,
                    event.actor_id,
                    event.payload_json,
                    event.previous_digest,
                    event.event_digest,
                    event.created_at,
                ),
            )
        return event

    def append_audit_event(
        self,
        *,
        key: str,
        organization_id: str,
        event_type: str,
        subject_id: str,
        actor_id: str,
        payload: dict[str, Any],
    ) -> AuditEvent:
        created_at = utc_now_iso()
        payload_json = canonical_json(payload)
        with self._connect() as connection:
            connection.execute("begin immediate")
            row = connection.execute(
                """
                select event_digest from audit_events
                where organization_id = ?
                order by created_at desc, id desc limit 1
                """,
                (organization_id,),
            ).fetchone()
            previous_digest = str(row["event_digest"]) if row else "GENESIS"
            event = AuditEvent(
                id=new_id("evt"),
                organization_id=organization_id,
                event_type=event_type,
                subject_id=subject_id,
                actor_id=actor_id,
                payload_json=payload_json,
                previous_digest=previous_digest,
                event_digest=audit_event_digest(
                    key=key,
                    previous_digest=previous_digest,
                    organization_id=organization_id,
                    event_type=event_type,
                    subject_id=subject_id,
                    actor_id=actor_id,
                    payload_json=payload_json,
                    created_at=created_at,
                ),
                created_at=created_at,
            )
            connection.execute(
                """
                insert into audit_events (
                    id, organization_id, event_type, subject_id, actor_id,
                    payload_json, previous_digest, event_digest, created_at
                ) values (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.id,
                    event.organization_id,
                    event.event_type,
                    event.subject_id,
                    event.actor_id,
                    event.payload_json,
                    event.previous_digest,
                    event.event_digest,
                    event.created_at,
                ),
            )
        return event

    def last_audit_digest(self, organization_id: str) -> str:
        row = self._fetch_one(
            """
            select event_digest from audit_events
            where organization_id = ?
            order by created_at desc, id desc limit 1
            """,
            (organization_id,),
        )
        return str(row["event_digest"]) if row else "GENESIS"

    def list_audit_events(
        self,
        organization_id: str,
        subject_id: str | None = None,
    ) -> list[AuditEvent]:
        if subject_id is None:
            rows = self._fetch_all(
                """
                select * from audit_events
                where organization_id = ?
                order by created_at, id
                """,
                (organization_id,),
            )
        else:
            rows = self._fetch_all(
                """
                select * from audit_events
                where organization_id = ? and subject_id = ?
                order by created_at, id
                """,
                (organization_id, subject_id),
            )
        return [self._model(AuditEvent, row) for row in rows]

    def health_counts(self) -> dict[str, int]:
        with self._connect() as connection:
            return {
                "users": connection.execute("select count(*) from users").fetchone()[0],
                "servers": connection.execute("select count(*) from mcp_servers").fetchone()[0],
                "tools": connection.execute("select count(*) from tool_manifests").fetchone()[0],
                "requests": connection.execute("select count(*) from gateway_requests").fetchone()[0],
                "approvals": connection.execute(
                    "select count(*) from approvals where status = 'pending'"
                ).fetchone()[0],
                "incidents": connection.execute("select count(*) from incidents").fetchone()[0],
                "executions": connection.execute("select count(*) from executions").fetchone()[0],
            }

    def plaintext_api_key_column_exists(self) -> bool:
        with self._connect() as connection:
            return "api_key" in self._table_columns(connection, "users")


repository = SQLiteRepository()
