"""Smoke-test the Compose stack: the gateway in its image, with Redis.

Run it after `docker compose up -d --wait`. It uses the standard library only,
so it runs on a bare CI runner:

    python scripts/docker_smoke.py [http://127.0.0.1:8000]

It checks that /health reports the Redis rate-limit backend and static mode, and
that one MCP tools/call with a public demo key executes.
"""

from __future__ import annotations

import json
import sys
import urllib.request

import ci_summary  # scripts/ci_summary.py

ROWS: list[tuple[str, str]] = []


def request(url: str, body: dict | None = None) -> dict:
    data = None if body is None else json.dumps(body).encode("utf-8")
    headers = {"Content-Type": "application/json", "Authorization": "Bearer msg-ops-demo"} if body else {}
    with urllib.request.urlopen(urllib.request.Request(url, data=data, headers=headers), timeout=10) as response:
        return json.load(response)


def check(step: str, condition: bool, observed: str) -> None:
    ROWS.append((step, observed))
    if not condition:
        raise AssertionError(f"{step}: {observed}")


def main(base: str) -> int:
    failed = False
    try:
        health = request(f"{base}/health")
        check(
            "health",
            health.get("rate_limit_backend") == "redis" and health.get("auth_mode") == "static",
            f"rate limits in {health.get('rate_limit_backend')}, auth {health.get('auth_mode')}, "
            f"database {health.get('database_backend')}",
        )
        call = request(
            f"{base}/mcp",
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
             "params": {"name": "kb.search", "arguments": {"query": "manifest quarantine"}}},
        )["result"]
        status = call["structuredContent"]["status"]
        check("MCP call", status == "executed" and not call["isError"], f"kb.search -> {status}")
    except Exception as exc:  # report what was seen so far
        failed = True
        print(f"FAILED: {exc}")
    for step, observed in ROWS:
        print(f"  {step:<9} {observed}")
    ci_summary.append(
        "Docker smoke test",
        "The gateway image and Redis, started with `docker compose up --wait`.",
        ["Step", "Observed"],
        ROWS,
        "**FAILED** (container logs are in the job output)." if failed else "**Passed.**",
    )
    if not failed:
        print("Docker smoke test passed.")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000"))
