"""Upstream MCP servers the gateway sits in front of (Streamable HTTP).

The gateway is the only client of an upstream: agents talk to the gateway, and
the gateway forwards a call only after its own controls. The client below is
deliberately small. It speaks `initialize`, `tools/list` and `tools/call`,
follows no redirects, caps response size, and never forwards the agent's
credentials: it has no access to them.
"""

from __future__ import annotations

import json
import os
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

import httpx

PROTOCOL_VERSION = "2025-11-25"
MAX_RESPONSE_BYTES = 1_048_576
TIMEOUT_SECONDS = 10.0
RISK_LEVELS = ("low", "medium", "high", "critical")


class UpstreamError(Exception):
    """The upstream could not be reached or answered outside the protocol."""


@dataclass(frozen=True, slots=True)
class UpstreamConfig:
    id: str
    name: str
    url: str
    prefix: str
    organization_id: str
    scope: str
    default_risk: str = "medium"
    risk: dict[str, str] = field(default_factory=dict, hash=False)

    def exposed_name(self, upstream_name: str) -> str:
        return f"{self.prefix}.{upstream_name}"

    def upstream_name(self, exposed_name: str) -> str | None:
        head, dot, tail = exposed_name.partition(".")
        return tail if dot and head == self.prefix and tail else None

    def risk_for(self, upstream_name: str) -> str:
        return self.risk.get(upstream_name, self.default_risk)


def load_upstreams(path: str | None = None) -> list[UpstreamConfig]:
    """Read `MSG_UPSTREAMS`, a JSON list. No file configured means no upstreams."""
    source = path if path is not None else os.getenv("MSG_UPSTREAMS", "").strip()
    if not source:
        return []
    raw = json.loads(Path(source).read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise ValueError("MSG_UPSTREAMS must contain a JSON list of upstream servers.")
    upstreams = []
    for entry in raw:
        config = UpstreamConfig(
            id=str(entry["id"]),
            name=str(entry["name"]),
            url=str(entry["url"]),
            prefix=str(entry["prefix"]),
            organization_id=str(entry["organization_id"]),
            scope=str(entry["scope"]),
            default_risk=str(entry.get("default_risk", "medium")),
            risk={str(key): str(value) for key, value in dict(entry.get("risk", {})).items()},
        )
        if not config.prefix.isidentifier():
            raise ValueError(f"Upstream prefix '{config.prefix}' must be a plain identifier.")
        if config.default_risk not in RISK_LEVELS or any(level not in RISK_LEVELS for level in config.risk.values()):
            raise ValueError(f"Upstream '{config.id}' uses an unknown risk level.")
        if not config.url.startswith(("http://", "https://")):
            raise ValueError(f"Upstream '{config.id}' must use an http(s) URL.")
        upstreams.append(config)
    if len({item.id for item in upstreams}) != len(upstreams) or len({item.prefix for item in upstreams}) != len(upstreams):
        raise ValueError("Upstream ids and prefixes must be unique.")
    return upstreams


class UpstreamClient(Protocol):
    def list_tools(self) -> list[dict[str, Any]]: ...

    def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]: ...


class HttpUpstreamClient:
    """One short session per operation: initialize, then the request."""

    def __init__(self, url: str, http: httpx.Client | None = None) -> None:
        self.url = url
        self._http = http or httpx.Client(timeout=TIMEOUT_SECONDS, follow_redirects=False)
        self._next_id = 0

    def list_tools(self) -> list[dict[str, Any]]:
        session = self._initialize()
        tools: list[dict[str, Any]] = []
        cursor: str | None = None
        for _ in range(20):
            params = {"cursor": cursor} if cursor else {}
            result = self._request("tools/list", params, session)
            page = result.get("tools", [])
            if not isinstance(page, list):
                raise UpstreamError("Upstream tools/list returned no tool list.")
            tools.extend(item for item in page if isinstance(item, dict))
            cursor = result.get("nextCursor")
            if not cursor:
                return tools
        raise UpstreamError("Upstream tools/list paginated too far.")

    def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        session = self._initialize()
        return self._request("tools/call", {"name": name, "arguments": arguments}, session)

    def _initialize(self) -> str | None:
        response = self._post(
            {
                "jsonrpc": "2.0",
                "id": self._id(),
                "method": "initialize",
                "params": {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": {"name": "mcp-security-gateway", "version": "upstream-proxy"},
                },
            },
            session=None,
            protocol=None,
        )
        self._result(response)
        session = response.headers.get("mcp-session-id")
        self._post({"jsonrpc": "2.0", "method": "notifications/initialized"}, session=session, protocol=PROTOCOL_VERSION)
        return session

    def _request(self, method: str, params: dict[str, Any], session: str | None) -> dict[str, Any]:
        response = self._post(
            {"jsonrpc": "2.0", "id": self._id(), "method": method, "params": params},
            session=session,
            protocol=PROTOCOL_VERSION,
        )
        return self._result(response)

    def _id(self) -> int:
        self._next_id += 1
        return self._next_id

    def _post(self, message: dict[str, Any], *, session: str | None, protocol: str | None) -> httpx.Response:
        # Only protocol headers. The agent's Authorization never exists here.
        headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
        if session:
            headers["Mcp-Session-Id"] = session
        if protocol:
            headers["MCP-Protocol-Version"] = protocol
        try:
            with self._http.stream("POST", self.url, headers=headers, content=json.dumps(message)) as response:
                if response.is_redirect:
                    raise UpstreamError("Upstream answered with a redirect, which the gateway does not follow.")
                body = bytearray()
                for chunk in response.iter_bytes():
                    body.extend(chunk)
                    if len(body) > MAX_RESPONSE_BYTES:
                        raise UpstreamError("Upstream response exceeds the gateway limit.")
                response._content = bytes(body)  # keep the capped body for parsing
                return response
        except httpx.HTTPError as exc:
            raise UpstreamError(f"Upstream unreachable: {type(exc).__name__}.") from exc

    def _result(self, response: httpx.Response) -> dict[str, Any]:
        if response.status_code == 202:
            return {}
        if response.status_code != 200:
            raise UpstreamError(f"Upstream answered HTTP {response.status_code}.")
        message = _parse_message(response)
        if "error" in message:
            raise UpstreamError(f"Upstream error {message['error'].get('code')}.")
        result = message.get("result")
        if not isinstance(result, dict):
            raise UpstreamError("Upstream response carried no result.")
        return result


def _parse_message(response: httpx.Response) -> dict[str, Any]:
    content_type = response.headers.get("content-type", "")
    text = response.content.decode("utf-8", errors="replace")
    if content_type.startswith("text/event-stream"):
        # The last JSON-RPC response in the stream answers the request.
        data = [line[5:].strip() for line in text.splitlines() if line.startswith("data:")]
        messages = [json.loads(item) for item in data if item]
        responses = [item for item in messages if isinstance(item, dict) and ("result" in item or "error" in item)]
        if not responses:
            raise UpstreamError("Upstream event stream carried no response.")
        return responses[-1]
    try:
        message = json.loads(text)
    except ValueError as exc:
        raise UpstreamError("Upstream response is not JSON.") from exc
    if not isinstance(message, dict):
        raise UpstreamError("Upstream response is not a JSON-RPC message.")
    return message


@dataclass
class InMemoryUpstream:
    """An upstream held in memory, for tests and Attack Lab replicas."""

    tools: list[dict[str, Any]]
    handler: Callable[[str, dict[str, Any]], dict[str, Any]]
    calls: list[tuple[str, dict[str, Any]]] = field(default_factory=list)

    def list_tools(self) -> list[dict[str, Any]]:
        return json.loads(json.dumps(self.tools))

    def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        self.calls.append((name, arguments))
        return self.handler(name, arguments)


class UpstreamRegistry:
    """Configured upstreams by server id, each with the client that reaches it."""

    def __init__(self, entries: dict[str, tuple[UpstreamConfig, UpstreamClient]] | None = None) -> None:
        self._entries = dict(entries or {})

    @classmethod
    def from_configs(cls, configs: list[UpstreamConfig]) -> UpstreamRegistry:
        return cls({config.id: (config, HttpUpstreamClient(config.url)) for config in configs})

    def get(self, server_id: str) -> tuple[UpstreamConfig, UpstreamClient] | None:
        return self._entries.get(server_id)

    def configs(self) -> list[UpstreamConfig]:
        return [config for config, _ in self._entries.values()]

    def __bool__(self) -> bool:
        return bool(self._entries)


def tool_definition(tool: dict[str, Any]) -> dict[str, Any]:
    """The parts of an upstream tool that are pinned: what the agent is shown."""
    return {
        "name": str(tool.get("name", "")),
        "description": str(tool.get("description", "")),
        "input_schema": tool.get("inputSchema") if isinstance(tool.get("inputSchema"), dict) else {},
        "annotations": tool.get("annotations") if isinstance(tool.get("annotations"), dict) else {},
    }
