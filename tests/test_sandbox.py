"""The public sandbox: per-IP limits, the body cap, resets and the test-server controls."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from mcp_security_gateway import config
from mcp_security_gateway.main import build_sandbox, create_app
from mcp_security_gateway.repository import SQLiteRepository
from mcp_security_gateway.sandbox import client_ip
from mcp_security_gateway.state import InMemoryRateLimitStore
from mcp_security_gateway.upstream import InMemoryUpstream, UpstreamConfig, UpstreamRegistry

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "examples"))
import poisoned_server  # noqa: E402

OPERATOR = {"Authorization": "Bearer msg-ops-demo"}
SECURITY = {"Authorization": "Bearer msg-security-demo"}
CONFIG = UpstreamConfig(
    id="up_notes",
    name="Notes MCP (poisoned test fixture)",
    url="http://upstream.test/mcp",
    prefix="notes",
    organization_id="org_danex",
    scope="notes:read",
    default_risk="low",
    risk={"export_notes": "high"},
)
KB_SEARCH = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {"name": "kb.search", "arguments": {"query": "manifest quarantine"}},
}


class Clock:
    def __init__(self) -> None:
        self.now = 1_000.0

    def __call__(self) -> float:
        return self.now


class FixtureControls:
    """Stands in for the test server's /rugpull and /reset over loopback."""

    def __init__(self) -> None:
        self.posts: list[str] = []
        self.down = False

    def __call__(self, url: str) -> None:
        if self.down:
            raise ConnectionRefusedError("test server down")
        self.posts.append(url.rsplit("/", 1)[1])
        poisoned_server.state["rug_pulled"] = url.endswith("/rugpull")


@pytest.fixture(autouse=True)
def sandbox_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    poisoned_server.state["rug_pulled"] = False
    monkeypatch.setenv("MSG_ENVIRONMENT", "sandbox")
    monkeypatch.setenv("MSG_SANDBOX_IP_LIMIT_PER_MINUTE", "10")
    monkeypatch.setenv("MSG_SANDBOX_RESET_MINUTES", "5")
    monkeypatch.setenv("MSG_TRUSTED_PROXY_HOPS", "0")


def fixture_upstream() -> InMemoryUpstream:
    upstream = InMemoryUpstream(tools=[], handler=poisoned_server.call)
    upstream.list_tools = lambda: json.loads(json.dumps(poisoned_server.tools()))  # type: ignore[method-assign]
    return upstream


def make_sandbox_client(tmp_path: Path, clock: Clock, controls: FixtureControls) -> tuple[TestClient, Any]:
    repo = SQLiteRepository(f"sqlite:///{tmp_path / 'gateway.db'}")
    rates = InMemoryRateLimitStore()
    registry = UpstreamRegistry({CONFIG.id: (CONFIG, fixture_upstream())})
    sandbox = build_sandbox(repo, rates, registry, clock=clock, fixture_post=controls)
    app = create_app(repo, rates, upstreams=registry, sandbox=sandbox)
    return TestClient(app), sandbox


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def controls() -> FixtureControls:
    return FixtureControls()


def test_local_mode_has_no_sandbox(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MSG_ENVIRONMENT", "local")
    repo = SQLiteRepository(f"sqlite:///{tmp_path / 'gateway.db'}")
    client = TestClient(create_app(repo, InMemoryRateLimitStore(), upstreams=UpstreamRegistry()))
    assert client.app.state.sandbox is None
    assert client.get("/sandbox").status_code == 404
    assert all(client.get("/health").status_code == 200 for _ in range(15))


@pytest.mark.parametrize(
    "url",
    ["http://example.com:8100", "https://127.0.0.1:8100", "http://127.0.0.1.example.com", "http://10.0.0.1"],
)
def test_the_test_server_is_reached_on_loopback_only(monkeypatch: pytest.MonkeyPatch, url: str) -> None:
    monkeypatch.setenv("MSG_SANDBOX_FIXTURE_URL", url)
    with pytest.raises(RuntimeError, match="loopback"):
        config.sandbox_fixture_url()


@pytest.mark.parametrize(
    ("forwarded_for", "peer", "hops", "expected"),
    [
        ("203.0.113.7", "10.0.0.2", 1, "203.0.113.7"),  # the proxy's entry
        ("198.51.100.1, 203.0.113.7", "10.0.0.2", 1, "203.0.113.7"),  # the client's own entry is ignored
        ("198.51.100.1, 203.0.113.7, 10.1.1.1", "10.0.0.2", 2, "203.0.113.7"),  # two proxies
        (None, "10.0.0.2", 1, "10.0.0.2"),  # no proxy on the way: the peer sent it
        ("203.0.113.7", "10.0.0.2", 2, "10.0.0.2"),  # fewer entries than proxies
        ("198.51.100.1, ", "10.0.0.2", 1, "10.0.0.2"),  # an empty entry is not an address
        ("198.51.100.1", "10.0.0.2", 0, "10.0.0.2"),  # no trusted proxy: the header is ignored
        (None, None, 1, "unknown"),
    ],
)
def test_client_ip_uses_the_trusted_proxies_entry(
    forwarded_for: str | None, peer: str | None, hops: int, expected: str
) -> None:
    assert client_ip(forwarded_for, peer, hops) == expected


def test_status_reports_the_limits(tmp_path: Path, clock: Clock, controls: FixtureControls) -> None:
    client, _ = make_sandbox_client(tmp_path, clock, controls)
    assert client.get("/health").json()["environment"] == "sandbox"
    status = client.get("/sandbox").json()
    assert status["shared"] is True
    assert status["reset_every_minutes"] == 5
    assert status["next_reset_in_seconds"] == 300
    assert status["ip_limit_per_minute"] == 10


def test_status_shows_the_caller_its_own_address(
    tmp_path: Path, clock: Clock, controls: FixtureControls, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("MSG_TRUSTED_PROXY_HOPS", "1")
    client, _ = make_sandbox_client(tmp_path, clock, controls)
    behind_proxy = client.get("/sandbox", headers={"X-Forwarded-For": "198.51.100.1, 203.0.113.7"}).json()
    assert behind_proxy["your_address"] == "203.0.113.7"
    assert behind_proxy["forwarded_for_entries"] == 2
    direct = client.get("/sandbox").json()
    assert direct["your_address"] == "testclient"
    assert direct["forwarded_for_entries"] == 0


def test_a_body_without_content_length_is_refused(tmp_path: Path, clock: Clock, controls: FixtureControls) -> None:
    client, _ = make_sandbox_client(tmp_path, clock, controls)
    chunked = client.post("/mcp", headers=OPERATOR, content=iter([json.dumps(KB_SEARCH).encode()]))
    assert chunked.status_code == 411
    assert client.post("/mcp", headers=OPERATOR, json=KB_SEARCH).status_code == 200


def test_each_address_gets_a_limit_per_minute(tmp_path: Path, clock: Clock, controls: FixtureControls) -> None:
    client, _ = make_sandbox_client(tmp_path, clock, controls)
    assert all(client.get("/health").status_code == 200 for _ in range(10))
    limited = client.get("/health")
    assert limited.status_code == 429
    assert 1 <= int(limited.headers["Retry-After"]) <= 60
    clock.now += 60
    assert client.get("/health").status_code == 200


def test_entries_written_by_the_client_do_not_change_its_address(
    tmp_path: Path, clock: Clock, controls: FixtureControls, monkeypatch: pytest.MonkeyPatch
) -> None:
    # One trusted proxy that appends the address it saw, after whatever the client sent.
    monkeypatch.setenv("MSG_TRUSTED_PROXY_HOPS", "1")
    client, _ = make_sandbox_client(tmp_path, clock, controls)
    for n in range(10):
        spoofed = [("x-forwarded-for", f"198.51.100.{n}"), ("x-forwarded-for", "203.0.113.7")]
        assert client.get("/health", headers=spoofed).status_code == 200
    joined = client.get("/health", headers={"X-Forwarded-For": "192.0.2.99, 203.0.113.7"})
    assert joined.status_code == 429
    other = client.get("/health", headers={"X-Forwarded-For": "198.51.100.1, 203.0.113.8"})
    assert other.status_code == 200


def test_a_scheduled_reset_restores_the_starting_data(tmp_path: Path, clock: Clock, controls: FixtureControls) -> None:
    client, sandbox = make_sandbox_client(tmp_path, clock, controls)
    assert client.post("/upstreams/up_notes/sync", headers=SECURITY).status_code == 200
    assert client.post("/mcp", headers=OPERATOR, json=KB_SEARCH).status_code == 200
    assert client.post("/sandbox/rug-pull", headers=SECURITY).status_code == 200
    assert client.get("/health").json()["requests"] == 1

    clock.now += 300
    health = client.get("/health").json()
    assert health["requests"] == 0
    assert sandbox.last_reset_reason == "schedule"
    assert controls.posts[-1] == "reset" and poisoned_server.state["rug_pulled"] is False
    upstreams = client.get("/upstreams", headers=SECURITY).json()
    assert [item["id"] for item in upstreams] == ["up_notes"]
    assert upstreams[0]["tools"] == []
    assert client.get("/sandbox").json()["next_reset_in_seconds"] == 300


def test_a_database_over_its_cap_is_reset(
    tmp_path: Path, clock: Clock, controls: FixtureControls, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, sandbox = make_sandbox_client(tmp_path, clock, controls)
    assert client.post("/mcp", headers=OPERATOR, json=KB_SEARCH).status_code == 200
    monkeypatch.setattr(sandbox.repo, "size_bytes", lambda: sandbox.settings.max_db_bytes + 1)
    assert client.get("/health").json()["requests"] == 0
    assert sandbox.last_reset_reason == "size"


def test_the_rug_pull_control_needs_an_admin(tmp_path: Path, clock: Clock, controls: FixtureControls) -> None:
    client, _ = make_sandbox_client(tmp_path, clock, controls)
    assert client.post("/sandbox/rug-pull").status_code == 401
    assert client.post("/sandbox/rug-pull", headers=OPERATOR).status_code == 403
    assert poisoned_server.state["rug_pulled"] is False
    assert client.post("/sandbox/rug-pull", headers=SECURITY).json() == {"status": "swapped"}
    assert poisoned_server.state["rug_pulled"] is True


def test_a_rug_pull_is_caught_on_the_next_call(tmp_path: Path, clock: Clock, controls: FixtureControls) -> None:
    client, _ = make_sandbox_client(tmp_path, clock, controls)
    assert client.post("/upstreams/up_notes/sync", headers=SECURITY).status_code == 200
    assert client.post("/sandbox/rug-pull", headers=SECURITY).status_code == 200
    call = {**KB_SEARCH, "params": {"name": "notes.search_notes", "arguments": {"query": "deploy"}}}
    result = client.post("/mcp", headers=OPERATOR, json=call).json()["result"]
    assert result["structuredContent"]["status"] == "denied"
    assert "changed since it was pinned" in result["structuredContent"]["reason"]


def test_a_manual_reset_waits_a_minute(tmp_path: Path, clock: Clock, controls: FixtureControls) -> None:
    client, sandbox = make_sandbox_client(tmp_path, clock, controls)
    assert client.post("/sandbox/reset", headers=OPERATOR).status_code == 403
    assert client.post("/sandbox/reset", headers=SECURITY).status_code == 200
    again = client.post("/sandbox/reset", headers=SECURITY)
    assert again.status_code == 429
    assert 1 <= int(again.headers["Retry-After"]) <= 60
    clock.now += 61
    assert client.post("/sandbox/reset", headers=SECURITY).status_code == 200
    assert sandbox.resets == 2 and sandbox.last_reset_reason == "manual"


def test_the_test_server_being_down_is_reported_not_fatal(
    tmp_path: Path, clock: Clock, controls: FixtureControls
) -> None:
    client, sandbox = make_sandbox_client(tmp_path, clock, controls)
    controls.down = True
    assert client.post("/sandbox/rug-pull", headers=SECURITY).status_code == 502
    assert client.post("/sandbox/reset", headers=SECURITY).status_code == 200
    assert sandbox.resets == 1
