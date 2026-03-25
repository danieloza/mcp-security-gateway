from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from mcp_security_gateway.main import create_app
from mcp_security_gateway.repository import SQLiteRepository
from mcp_security_gateway.state import InMemoryRateLimitStore


def make_client(tmp_path: Path) -> TestClient:
    app = create_app(SQLiteRepository(f"sqlite:///{tmp_path / 'gateway.db'}"), InMemoryRateLimitStore())
    return TestClient(app)


def test_health_endpoint(tmp_path: Path) -> None:
    client = make_client(tmp_path)
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["service"] == "mcp-security-gateway"


def test_safe_request_is_approved(tmp_path: Path) -> None:
    client = make_client(tmp_path)
    response = client.post(
        "/requests",
        headers={"X-API-Key": "msg-ops-demo"},
        json={"mcp_server_id": "mcp_docs", "tool_name": "kb.search", "requested_scope": "docs:read", "justification": "Look up internal documentation before responding.", "estimated_tokens": 300, "arguments": {"query": "redis timeout playbook"}},
    )
    assert response.status_code == 201
    assert response.json()["status"] == "approved"


def test_high_risk_request_requires_approval(tmp_path: Path) -> None:
    client = make_client(tmp_path)
    create_response = client.post(
        "/requests",
        headers={"X-API-Key": "msg-ops-demo"},
        json={"mcp_server_id": "mcp_github", "tool_name": "repo.write_file", "requested_scope": "repo:write", "justification": "Apply generated docs patch to repository.", "estimated_tokens": 1200, "arguments": {"path": "README.md", "content": "updated"}},
    )
    approvals_response = client.get("/approvals", headers={"X-API-Key": "msg-ops-demo"})
    assert create_response.status_code == 201
    assert create_response.json()["status"] == "awaiting_approval"
    assert approvals_response.json()[0]["status"] == "pending"


def test_production_admin_scope_is_blocked(tmp_path: Path) -> None:
    client = make_client(tmp_path)
    response = client.post(
        "/requests",
        headers={"X-API-Key": "msg-ops-demo"},
        json={"mcp_server_id": "mcp_prod_ops", "tool_name": "ops.restart_service", "requested_scope": "ops:admin", "justification": "Restart a production service through the MCP gateway.", "estimated_tokens": 800, "arguments": {"service": "payments"}},
    )
    incidents_response = client.get("/incidents", headers={"X-API-Key": "msg-ops-demo"})
    assert response.status_code == 201
    assert response.json()["status"] == "blocked"
    assert incidents_response.json()[0]["severity"] == "critical"


def test_redacts_secrets_in_audit_log(tmp_path: Path) -> None:
    client = make_client(tmp_path)
    response = client.post(
        "/requests",
        headers={"X-API-Key": "msg-ops-demo"},
        json={"mcp_server_id": "mcp_github", "tool_name": "repo.write_file", "requested_scope": "repo:write", "justification": "Write config after rotation workflow.", "estimated_tokens": 900, "arguments": {"api_key": "abcd1234", "content": "temporary secret token"}},
    )
    assert response.status_code == 201
    assert "[REDACTED]" in response.json()["redacted_arguments"]
    assert "abcd1234" not in response.json()["redacted_arguments"]


def test_security_admin_can_decide_approval(tmp_path: Path) -> None:
    client = make_client(tmp_path)
    create_response = client.post(
        "/requests",
        headers={"X-API-Key": "msg-ops-demo"},
        json={"mcp_server_id": "mcp_github", "tool_name": "repo.write_file", "requested_scope": "repo:write", "justification": "Apply a small approved content fix.", "estimated_tokens": 600, "arguments": {"path": "notes.md", "content": "updated"}},
    )
    request_id = create_response.json()["id"]
    approval_id = client.get("/approvals", headers={"X-API-Key": "msg-ops-demo"}).json()[0]["id"]
    decision_response = client.post(f"/approvals/{approval_id}/decision", headers={"X-API-Key": "msg-security-demo"}, json={"decision": "approved"})
    request_response = client.get(f"/requests/{request_id}", headers={"X-API-Key": "msg-ops-demo"})
    assert decision_response.status_code == 200
    assert request_response.json()["status"] == "approved"
