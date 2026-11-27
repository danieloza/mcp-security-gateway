"""Smoke-test the sandbox image: the gateway and both upstream servers in one container.

    docker build -f deploy/demo/Dockerfile -t mcp-security-gateway-sandbox .
    docker run -d --name sandbox -p 127.0.0.1:8010:8000 mcp-security-gateway-sandbox
    python scripts/sandbox_smoke.py http://127.0.0.1:8010

Standard library only. It waits for /health, then checks that /health reports
the sandbox, that a security admin can sync the bundled test server (so the
processes run in the container), that a clean call executes, that the bundled
retrieval server syncs and answers a search and its trace, and that after the
sandbox's rug-pull control the next call is denied.
"""

from __future__ import annotations

import json
import sys
import time
import urllib.error
import urllib.request

import ci_summary  # scripts/ci_summary.py

OPERATOR = "msg-ops-demo"
SECURITY = "msg-security-demo"
ROWS: list[tuple[str, str]] = []


def request(url: str, body: dict | None = None, key: str | None = None) -> dict:
    data = None if body is None else json.dumps(body).encode("utf-8")
    headers = {"Content-Type": "application/json"} if body is not None else {}
    if key:
        headers["Authorization"] = f"Bearer {key}"
    with urllib.request.urlopen(urllib.request.Request(url, data=data, headers=headers), timeout=10) as response:
        return json.load(response)


def wait_for_health(base: str, timeout: float = 90.0) -> dict:
    deadline = time.monotonic() + timeout
    while True:
        try:
            return request(f"{base}/health")
        except (urllib.error.URLError, ConnectionError):
            if time.monotonic() > deadline:
                raise
            time.sleep(1)


def call(base: str, name: str, arguments: dict) -> dict:
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, "arguments": arguments}}
    return request(f"{base}/mcp", body, OPERATOR)["result"]["structuredContent"]


def check(step: str, condition: bool, observed: str) -> None:
    ROWS.append((step, observed))
    if not condition:
        raise AssertionError(f"{step}: {observed}")


def main(base: str) -> int:
    failed = False
    try:
        health = wait_for_health(base)
        check("health", health.get("environment") == "sandbox" and health.get("auth_mode") == "static",
              f"environment {health.get('environment')}, auth {health.get('auth_mode')}")
        status = request(f"{base}/sandbox")
        check("limits", status.get("shared") is True,
              f"{status.get('ip_limit_per_minute')} requests/min per address, "
              f"reset every {status.get('reset_every_minutes')} min")
        sync = request(f"{base}/upstreams/up_notes/sync", {}, SECURITY)
        pinned = sorted(item["tool"] for item in sync["results"] if item["status"] == "pinned")
        check("sync", pinned == ["notes.export_notes", "notes.search_notes"], f"pinned {', '.join(pinned) or 'nothing'}")
        clean = call(base, "notes.search_notes", {"query": "zzz-no-such-note"})
        check("clean call", clean.get("status") == "executed", f"notes.search_notes -> {clean.get('status')}")
        rag_sync = request(f"{base}/upstreams/up_rag/sync", {}, SECURITY)
        rag_pinned = sorted(item["tool"] for item in rag_sync["results"] if item["status"] == "pinned")
        check("rag sync", rag_pinned == ["rag.get_trace", "rag.search"], f"pinned {', '.join(rag_pinned) or 'nothing'}")
        found = call(base, "rag.search", {"question": "W jakim terminie klient może zgłosić reklamację?", "limit": 2})
        answer = ((found.get("result") or {}).get("structuredContent")) or {}
        evidence = answer.get("results", [])
        check("rag search", found.get("status") == "executed" and bool(evidence),
              f"rag.search -> {found.get('status')}, top source {evidence[0]['source'] if evidence else 'none'}")
        traced = call(base, "rag.get_trace", {"query_id": answer.get("query_id", "")})
        route = (((traced.get("result") or {}).get("structuredContent")) or {}).get("route")
        check("rag trace", traced.get("status") == "executed" and route == "mcp_lexical",
              f"rag.get_trace -> {traced.get('status')}, route {route}")
        request(f"{base}/sandbox/rug-pull", {}, SECURITY)
        swapped = call(base, "notes.search_notes", {"query": "zzz-no-such-note"})
        check("rug pull", swapped.get("status") == "denied", f"after the swap -> {swapped.get('status')}")
    except Exception as exc:  # report what was seen so far
        failed = True
        print(f"FAILED: {exc}")
    for step, observed in ROWS:
        print(f"  {step:<10} {observed}")
    ci_summary.append(
        "Sandbox smoke test",
        "The public sandbox image: the gateway, the poisoned test server and the retrieval server in one container.",
        ["Step", "Observed"],
        ROWS,
        "**FAILED** (container logs are in the job output)." if failed else "**Passed.**",
    )
    if not failed:
        print("Sandbox smoke test passed.")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8010"))
