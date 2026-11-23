"""The public sandbox: one shared, disposable gateway for anyone to try.

Active only with MSG_ENVIRONMENT=sandbox. On top of the gateway's own limits it adds:

- a request limit per client IP;
- 411 for a request body without Content-Length, so the body cap cannot be skipped
  by chunked encoding;
- a reset of all data on a schedule and whenever the database outgrows its cap;
- controls for the bundled poisoned test server (swap its tool, reset it), which
  the sandbox reaches on loopback only.

Nothing here runs in local or production mode.
"""

from __future__ import annotations

import logging
import math
import time
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from threading import Lock
from typing import Any

from mcp_security_gateway import config
from mcp_security_gateway.repository import SQLiteRepository


log = logging.getLogger(__name__)

MANUAL_RESET_COOLDOWN_SECONDS = 60
WINDOW_SECONDS = 60
MAX_TRACKED_CLIENTS = 4_096
BODY_METHODS = frozenset({"POST", "PUT", "PATCH"})


def client_ip(forwarded_for: str | None, peer: str | None, trusted_hops: int) -> str:
    """Return the client address as the trusted proxies saw it.

    `forwarded_for` is the raw X-Forwarded-For value: comma-separated addresses,
    oldest first. Each proxy appends the address it received the request from,
    and nothing stops a client from sending the header with any addresses it
    likes. Render appends to it and never clears it, so the leftmost entries are
    whatever the client wrote. `trusted_hops` is how many proxies in front of the
    sandbox append an entry; `peer` is the TCP peer (the last proxy), or None.

    With trusted_hops == 0 there is no proxy: the peer is the client.

    The entry `trusted_hops` places from the right is the one the outermost
    trusted proxy wrote. With fewer entries than that, the request did not pass
    through every trusted proxy (a local run, a health check), so the peer sent
    it. A client cannot remove what a proxy appends, so it cannot reach that
    case to pick its own address.
    """
    if trusted_hops > 0 and forwarded_for:
        entries = [entry.strip() for entry in forwarded_for.split(",")]
        if len(entries) >= trusted_hops and entries[-trusted_hops]:
            return entries[-trusted_hops]
    return peer or "unknown"


class IPRateLimiter:
    """A fixed one-minute window per client address, held in memory.

    The sandbox runs as one instance, so memory is the right store. Expired
    windows are dropped once the table grows, which bounds it under a flood of
    distinct addresses.
    """

    def __init__(self, limit_per_minute: int, clock: Callable[[], float]) -> None:
        self.limit = limit_per_minute
        self._clock = clock
        self._windows: dict[str, tuple[int, float]] = {}
        self._lock = Lock()

    def hit(self, address: str) -> int | None:
        """Count one request. Return the seconds to wait when over the limit, else None."""
        now = self._clock()
        with self._lock:
            if len(self._windows) >= MAX_TRACKED_CLIENTS:
                self._windows = {key: value for key, value in self._windows.items() if value[1] > now}
            count, resets_at = self._windows.get(address, (0, now + WINDOW_SECONDS))
            if resets_at <= now:
                count, resets_at = 0, now + WINDOW_SECONDS
            count += 1
            self._windows[address] = (count, resets_at)
        if count > self.limit:
            return max(1, math.ceil(resets_at - now))
        return None


def post_to_fixture(url: str) -> None:
    request = urllib.request.Request(
        url,
        data=b"{}",
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=3) as response:  # noqa: S310 - loopback only, see config
        response.read()


@dataclass(frozen=True, slots=True)
class SandboxSettings:
    ip_limit_per_minute: int
    reset_seconds: int
    max_db_bytes: int
    trusted_hops: int
    fixture_url: str

    @classmethod
    def from_environment(cls) -> SandboxSettings:
        return cls(
            ip_limit_per_minute=config.sandbox_ip_limit_per_minute(),
            reset_seconds=config.sandbox_reset_seconds(),
            max_db_bytes=config.sandbox_max_db_bytes(),
            trusted_hops=config.trusted_proxy_hops(),
            fixture_url=config.sandbox_fixture_url(),
        )


class Sandbox:
    def __init__(
        self,
        settings: SandboxSettings,
        repo: SQLiteRepository,
        on_reset: Callable[[], None],
        *,
        clock: Callable[[], float] = time.monotonic,
        fixture_post: Callable[[str], None] = post_to_fixture,
    ) -> None:
        self.settings = settings
        self.repo = repo
        self._on_reset = on_reset
        self._clock = clock
        self._fixture_post = fixture_post
        self._lock = Lock()
        self.limiter = IPRateLimiter(settings.ip_limit_per_minute, clock)
        self.last_reset_at = clock()
        self.last_manual_reset_at: float | None = None
        self.last_reset_reason = "start"
        self.resets = 0

    def admit(self, forwarded_for: str | None, peer: str | None) -> int | None:
        """Count a request against its client's limit. Seconds to wait, or None."""
        return self.limiter.hit(client_ip(forwarded_for, peer, self.settings.trusted_hops))

    def caller(self, forwarded_for: str | None, peer: str | None) -> dict[str, Any]:
        """What the sandbox sees of the caller: its address, and how many entries arrived.

        After a deploy, compare `your_address` with your public address: a private
        address means MSG_TRUSTED_PROXY_HOPS is too low. With no X-Forwarded-For
        sent by you, `forwarded_for_entries` is the number of proxies that appended one.
        """
        return {
            "your_address": client_ip(forwarded_for, peer, self.settings.trusted_hops),
            "forwarded_for_entries": len(forwarded_for.split(",")) if forwarded_for else 0,
        }

    def due_reset(self) -> str | None:
        if self._clock() - self.last_reset_at >= self.settings.reset_seconds:
            return "schedule"
        if self.repo.size_bytes() > self.settings.max_db_bytes:
            return "size"
        return None

    def reset_if_due(self) -> str | None:
        reason = self.due_reset()
        if reason is not None:
            self.reset(reason)
        return reason

    def reset(self, reason: str) -> None:
        with self._lock:
            # A request that waited on the lock may find the reset already done.
            if reason != "manual" and self.due_reset() is None:
                return
            self.repo.reset()
            self._on_reset()
            try:
                self._fixture_post(f"{self.settings.fixture_url}/reset")
            except OSError as exc:
                log.warning("sandbox reset: the test server did not answer: %s", exc)
            self.last_reset_at = self._clock()
            self.last_reset_reason = reason
            self.resets += 1
        log.info("sandbox reset (%s)", reason)

    def manual_reset(self) -> int | None:
        """Reset on request, at most once a minute. Seconds to wait, or None once done."""
        with self._lock:
            now = self._clock()
            if self.last_manual_reset_at is not None:
                wait = MANUAL_RESET_COOLDOWN_SECONDS - (now - self.last_manual_reset_at)
                if wait > 0:
                    return max(1, math.ceil(wait))
            self.last_manual_reset_at = now
        self.reset("manual")
        return None

    def rug_pull(self) -> None:
        """Make the test server swap the description of one of its tools."""
        self._fixture_post(f"{self.settings.fixture_url}/rugpull")

    def status(self) -> dict[str, Any]:
        elapsed = self._clock() - self.last_reset_at
        return {
            "environment": "sandbox",
            "shared": True,
            "reset_every_minutes": self.settings.reset_seconds // 60,
            "next_reset_in_seconds": max(0, math.ceil(self.settings.reset_seconds - elapsed)),
            "last_reset_reason": self.last_reset_reason,
            "resets": self.resets,
            "ip_limit_per_minute": self.settings.ip_limit_per_minute,
            "max_request_bytes": config.max_request_bytes(),
            "max_database_bytes": self.settings.max_db_bytes,
        }
