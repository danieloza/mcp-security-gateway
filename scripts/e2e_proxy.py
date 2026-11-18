"""Proxy mode end to end, over real HTTP, with the official MCP Python SDK as the agent.

It starts the poisoned example server and the gateway as separate processes on
free loopback ports, with a throwaway database, then plays one scenario:

1. before any sync, the agent sees none of the upstream's tools;
2. an operator may not sync; a security admin syncs and both tools are pinned;
3. a clean call executes, an injected output is withheld, a high-risk call waits
   for approval;
4. the upstream swaps a description; the next call is denied without any sync,
   and the tool disappears from the agent's list;
5. a new sync reports the rug pull, with no second rug-pull incident.

Every step is asserted. The script exits non-zero on the first failure and stops
both servers either way. Run it from the repository root:

    python -m pip install -e ".[e2e]"
    python scripts/e2e_proxy.py
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

import httpx
from mcp import ClientSession
from mcp.client.streamable_http import create_mcp_http_client, streamable_http_client

ROOT = Path(__file__).resolve().parents[1]
OPERATOR = {"Authorization": "Bearer msg-ops-demo"}
SECURITY = {"Authorization": "Bearer msg-security-demo"}
ROWS: list[tuple[str, str]] = []


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_until_up(url: str, process: subprocess.Popen[bytes], seconds: float = 30) -> None:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"{url} exited early with code {process.returncode}")
        with contextlib.suppress(httpx.HTTPError):
            if httpx.get(url, timeout=2).status_code < 500:
                return
        time.sleep(0.3)
    raise RuntimeError(f"{url} did not come up within {seconds} s")


def check(step: str, condition: bool, observed: str) -> None:
    ROWS.append((step, observed))
    if not condition:
        raise AssertionError(f"{step}: {observed}")


class Agent:
    def __init__(self, gateway: str) -> None:
        self.url = f"{gateway}/mcp"

    async def tools(self) -> list[str]:
        async with self._session() as session:
            return [tool.name for tool in (await session.list_tools()).tools]

    async def call(self, name: str, arguments: dict[str, Any]) -> tuple[dict[str, Any], bool]:
        async with self._session() as session:
            result = await session.call_tool(name, arguments)
            return result.structured_content or {}, bool(result.is_error)

    @contextlib.asynccontextmanager
    async def _session(self):  # type: ignore[no-untyped-def]
        http = create_mcp_http_client(headers=OPERATOR)
        async with http, streamable_http_client(self.url, http_client=http) as streams:
            async with ClientSession(streams[0], streams[1]) as session:
                await session.initialize()
                yield session


async def scenario(gateway: str, upstream: str) -> None:
    agent = Agent(gateway)
    rest = httpx.Client(base_url=gateway, timeout=15)

    listed = await agent.tools()
    check("before sync", not any(name.startswith("notes.") for name in listed), f"agent sees {sorted(listed)}")

    denied = rest.post("/upstreams/up_notes/sync", headers=OPERATOR)
    check("operator sync", denied.status_code == 403, f"HTTP {denied.status_code}")
    synced = {item["tool"]: item["status"] for item in rest.post("/upstreams/up_notes/sync", headers=SECURITY).json()["results"]}
    check("admin sync", synced == {"notes.search_notes": "pinned", "notes.export_notes": "pinned"}, json.dumps(synced))

    clean, is_error = await agent.call("notes.search_notes", {"query": "rota"})
    reached = "Sandra" in json.dumps(clean)
    check(
        "clean call",
        clean.get("status") == "executed" and not is_error and reached,
        f"{clean.get('status')}, isError={is_error}, " + ("note reached the agent" if reached else "note missing"),
    )

    blocked, is_error = await agent.call("notes.search_notes", {"query": "deploy"})
    findings = sorted({item["type"] for item in blocked.get("findings", [])})
    leaked = "id_rsa" in json.dumps(blocked)
    check(
        "injected output",
        blocked.get("status") == "response_blocked" and is_error and not leaked
        and {"instruction_override", "concealment", "secret_file_coaxing"} <= set(findings),
        f"{blocked.get('status')}, isError={is_error}, findings={findings}, "
        + ("the note's text reached the agent" if leaked else "text withheld"),
    )
    request = rest.get(f"/requests/{blocked['requestId']}", headers=OPERATOR).json()
    check("operator view", request["execution_status"] == "output_withheld", f"execution_status={request['execution_status']}")

    held, is_error = await agent.call("notes.export_notes", {"destination": "archive"})
    check("high-risk call", held.get("status") == "approval_required" and not is_error, f"{held.get('status')}")

    httpx.post(f"{upstream}/rugpull", timeout=5).raise_for_status()
    pulled, is_error = await agent.call("notes.search_notes", {"query": "rota"})
    check(
        "after rug pull",
        pulled.get("status") == "denied" and is_error and "changed since it was pinned" in pulled.get("reason", ""),
        f"{pulled.get('status')}: {pulled.get('reason')}",
    )
    listed = await agent.tools()
    check("tool list", "notes.search_notes" not in listed, "notes.search_notes no longer listed")

    resynced = {item["tool"]: item for item in rest.post("/upstreams/up_notes/sync", headers=SECURITY).json()["results"]}
    quarantined = resynced["notes.search_notes"]
    check(
        "new sync",
        quarantined["status"] == "quarantined" and quarantined.get("reason") == "rug_pull",
        f"{quarantined['status']} ({quarantined.get('reason')}), changed {quarantined.get('changed_fields')}",
    )
    rug_pulls = [item for item in rest.get("/incidents", headers=OPERATOR).json() if "Rug pull" in item["summary"]]
    check("incidents", len(rug_pulls) == 1, f"{len(rug_pulls)} rug-pull incident")


def write_summary(failed: bool) -> None:
    """Show the steps on the GitHub Actions run page, when running there."""
    target = os.environ.get("GITHUB_STEP_SUMMARY")
    if not target:
        return
    import importlib.metadata

    lines = [
        "### Proxy mode end to end",
        "",
        f"The poisoned example server and the gateway over HTTP, with MCP Python SDK {importlib.metadata.version('mcp')} as the agent.",
        "",
        "| Step | Observed |",
        "| --- | --- |",
    ]
    lines += [f"| {step} | {observed.replace('|', '/')} |" for step, observed in ROWS]
    lines += ["", "**FAILED** (server logs are in the job output)." if failed else "**All steps passed.**", ""]
    with open(target, "a", encoding="utf-8") as summary:
        summary.write("\n".join(lines) + "\n")


def main() -> int:
    import importlib.metadata

    with tempfile.TemporaryDirectory(prefix="gateway-e2e-") as tmp:
        upstream_port, gateway_port = free_port(), free_port()
        upstream_url = f"http://127.0.0.1:{upstream_port}"
        gateway_url = f"http://127.0.0.1:{gateway_port}"
        config = json.loads((ROOT / "examples" / "upstreams.json").read_text(encoding="utf-8"))
        config[0]["url"] = f"{upstream_url}/mcp"
        upstreams = Path(tmp) / "upstreams.json"
        upstreams.write_text(json.dumps(config), encoding="utf-8")
        env = {
            **os.environ,
            "MSG_ENVIRONMENT": "local",
            "MSG_AUTH_MODE": "static",
            "MSG_UPSTREAMS": str(upstreams),
            "MSG_DATABASE_URL": f"sqlite:///{(Path(tmp) / 'gateway.db').as_posix()}",
        }
        logs = {name: open(Path(tmp) / f"{name}.log", "wb") for name in ("upstream", "gateway")}  # noqa: SIM115
        processes = {
            "upstream": subprocess.Popen(
                [sys.executable, "-c",
                 "import sys, uvicorn; sys.path.insert(0, 'examples'); import poisoned_server; "
                 f"uvicorn.run(poisoned_server.app, host='127.0.0.1', port={upstream_port}, log_level='warning')"],
                cwd=ROOT, env=env, stdout=logs["upstream"], stderr=subprocess.STDOUT,
            ),
            "gateway": subprocess.Popen(
                [sys.executable, "-m", "uvicorn", "mcp_security_gateway.main:app",
                 "--host", "127.0.0.1", "--port", str(gateway_port), "--log-level", "warning"],
                cwd=ROOT, env=env, stdout=logs["gateway"], stderr=subprocess.STDOUT,
            ),
        }
        failed = False
        try:
            wait_until_up(f"{upstream_url}/mcp", processes["upstream"])
            wait_until_up(f"{gateway_url}/health", processes["gateway"])
            asyncio.run(scenario(gateway_url, upstream_url))
        except Exception as exc:  # report, then show the server logs
            failed = True
            print(f"FAILED: {exc}")
        finally:
            for process in processes.values():
                process.terminate()
                with contextlib.suppress(subprocess.TimeoutExpired):
                    process.wait(timeout=10)
            for log in logs.values():
                log.close()
        width = max((len(step) for step, _ in ROWS), default=0)
        print(f"MCP Python SDK {importlib.metadata.version('mcp')}, gateway {gateway_url}, upstream {upstream_url}")
        for step, observed in ROWS:
            print(f"  {step:<{width}}  {observed}")
        write_summary(failed)
        if failed:
            for name in logs:
                print(f"--- {name} log ---")
                print((Path(tmp) / f"{name}.log").read_text(encoding="utf-8", errors="replace")[-4000:])
            return 1
        print("Proxy end to end: all steps passed.")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
