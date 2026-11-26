from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from mcp_security_gateway.main import create_app
from mcp_security_gateway.repository import SQLiteRepository
from mcp_security_gateway.state import InMemoryRateLimitStore
from mcp_security_gateway.tool_names import FUNCTION_NAME, alias_map, resolve, wire_name

OPERATOR = {"Authorization": "Bearer msg-ops-demo"}
ORG = "org_danex"
SEED_TOOLS = {
    "kb.search": "kb_search",
    "repo.write_file": "repo_write_file",
    "ops.restart_service": "ops_restart_service",
}


def make_client(tmp_path: Path) -> tuple[TestClient, SQLiteRepository]:
    repo = SQLiteRepository(f"sqlite:///{tmp_path / 'gateway.db'}")
    return TestClient(create_app(repo, InMemoryRateLimitStore())), repo


def mcp(client: TestClient, method: str, params: dict[str, Any], query: str = "", name: str | None = None) -> Any:
    headers = {**OPERATOR, "Mcp-Method": method}
    if name:
        headers["Mcp-Name"] = name
    return client.post(
        f"/mcp{query}",
        headers=headers,
        json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
    )


def call(client: TestClient, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    response = mcp(client, "tools/call", {"name": name, "arguments": arguments}, name=name)
    assert response.status_code == 200
    return response.json()["result"]["structuredContent"]


# --- The mapping rule ---------------------------------------------------------


@pytest.mark.parametrize(("canonical", "alias"), sorted(SEED_TOOLS.items()))
def test_seed_tool_names_map_to_underscores(canonical: str, alias: str) -> None:
    assert wire_name(canonical) == alias


@pytest.mark.parametrize(
    "canonical",
    ["kb.search", "notes/export notes", "zażółć.gęślą", "a" * 64, "x." * 80, "tool:v2@prod", "-.-"],
)
def test_every_alias_is_a_valid_function_name(canonical: str) -> None:
    alias = wire_name(canonical)
    assert FUNCTION_NAME.match(alias)
    assert wire_name(canonical) == alias


def test_a_valid_name_is_its_own_alias() -> None:
    assert wire_name("kb_search") == "kb_search"
    assert wire_name("a" * 64) == "a" * 64


def test_long_names_with_a_shared_start_get_different_aliases() -> None:
    first = "upstream." + "a" * 70 + ".read"
    second = "upstream." + "a" * 70 + ".write"
    assert wire_name(first) != wire_name(second)
    assert len(wire_name(first)) == 64
    assert len(wire_name(second)) == 64


# --- Collisions ---------------------------------------------------------------


def test_an_alias_two_tools_would_share_goes_to_neither() -> None:
    aliases = alias_map(["kb.search", "kb_search", "ops.restart_service"])
    assert aliases == {"ops_restart_service": "ops.restart_service"}


def test_a_collision_among_non_canonical_spellings_goes_to_neither() -> None:
    assert alias_map(["notes.export", "notes/export", "kb.search"]) == {"kb_search": "kb.search"}


def test_a_colliding_alias_does_not_resolve_but_canonical_names_do() -> None:
    names = ["kb.search", "kb_search"]
    assert resolve("kb.search", names) == "kb.search"
    assert resolve("kb_search", names) == "kb_search"
    assert resolve("kb-search", names) == "kb-search"


def test_resolve_maps_an_alias_back_and_leaves_unknown_names() -> None:
    names = list(SEED_TOOLS)
    assert resolve("kb_search", names) == "kb.search"
    assert resolve("kb.search", names) == "kb.search"
    assert resolve("missing_tool", names) == "missing_tool"


# --- Through /mcp ---------------------------------------------------------------


def test_default_listing_keeps_canonical_names(tmp_path: Path) -> None:
    client, _ = make_client(tmp_path)
    tools = mcp(client, "tools/list", {}).json()["result"]["tools"]
    assert {tool["name"] for tool in tools} >= set(SEED_TOOLS)
    assert all("gateway/canonicalName" not in tool["_meta"] for tool in tools)


def test_underscore_listing_exposes_valid_function_names(tmp_path: Path) -> None:
    client, _ = make_client(tmp_path)
    tools = mcp(client, "tools/list", {}, query="?tool_names=underscore").json()["result"]["tools"]
    assert all(FUNCTION_NAME.match(tool["name"]) for tool in tools)
    canonical_of = {tool["name"]: tool["_meta"]["gateway/canonicalName"] for tool in tools}
    assert {alias: canonical_of[alias] for alias in SEED_TOOLS.values()} == {v: k for k, v in SEED_TOOLS.items()}


def test_unknown_name_style_is_rejected(tmp_path: Path) -> None:
    client, _ = make_client(tmp_path)
    response = mcp(client, "tools/list", {}, query="?tool_names=camel")
    assert response.status_code == 400


def test_alias_call_runs_and_records_the_canonical_name(tmp_path: Path) -> None:
    client, repo = make_client(tmp_path)
    result = call(client, "kb_search", {"query": "manifest quarantine"})
    assert result["status"] == "executed"
    request = repo.get_request(ORG, result["requestId"])
    assert request is not None
    assert request.tool_name == "kb.search"


def test_alias_call_meets_the_same_policy_as_the_canonical_name(tmp_path: Path) -> None:
    client, _ = make_client(tmp_path)
    by_alias = call(client, "ops_restart_service", {"service": "payments"})
    by_canonical = call(client, "ops.restart_service", {"service": "payments"})
    assert by_alias["status"] == by_canonical["status"] == "denied"
    assert by_alias["reason"] == by_canonical["reason"]


def test_quarantined_tool_keeps_its_alias_and_is_refused_through_it(tmp_path: Path) -> None:
    client, repo = make_client(tmp_path)
    manifest = repo.get_tool_by_name(ORG, "kb.search")
    assert manifest is not None
    repo.set_tool_trust(ORG, manifest.id, "quarantined")

    listed = {tool["name"] for tool in mcp(client, "tools/list", {}, query="?tool_names=underscore").json()["result"]["tools"]}
    assert "kb_search" not in listed
    assert "repo_write_file" in listed

    by_alias = call(client, "kb_search", {"query": "rota"})
    by_canonical = call(client, "kb.search", {"query": "rota"})
    assert by_alias["status"] == by_canonical["status"] == "denied"
    assert by_alias["reason"] == by_canonical["reason"]
    assert "Unknown MCP tool" not in by_alias["reason"]
