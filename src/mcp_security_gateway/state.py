from __future__ import annotations

import time
from dataclasses import dataclass
from threading import Lock

from redis import Redis
from redis.exceptions import RedisError

from mcp_security_gateway.config import is_production
from mcp_security_gateway.security import hash_secret


@dataclass(frozen=True, slots=True)
class RateLimitResult:
    count: int
    limit: int
    remaining: int


class RateLimitStore:
    backend_name = "memory"

    def increment(self, subject: str, *, limit: int = 5, window_seconds: int = 60) -> RateLimitResult:
        raise NotImplementedError


class InMemoryRateLimitStore(RateLimitStore):
    backend_name = "memory"

    def __init__(self) -> None:
        self.counts: dict[str, tuple[int, float]] = {}
        self._lock = Lock()

    def increment(self, subject: str, *, limit: int = 5, window_seconds: int = 60) -> RateLimitResult:
        key = hash_secret(subject)
        now = time.monotonic()
        with self._lock:
            count, expires_at = self.counts.get(key, (0, now + window_seconds))
            if expires_at <= now:
                count, expires_at = 0, now + window_seconds
            count += 1
            self.counts[key] = (count, expires_at)
        return RateLimitResult(count=count, limit=limit, remaining=max(0, limit - count))


class RedisRateLimitStore(RateLimitStore):
    backend_name = "redis"
    _INCREMENT_SCRIPT = """
    local current = redis.call('INCR', KEYS[1])
    if current == 1 then
      redis.call('EXPIRE', KEYS[1], ARGV[1])
    end
    return current
    """

    def __init__(self, client: Redis) -> None:
        self.client = client

    def increment(self, subject: str, *, limit: int = 5, window_seconds: int = 60) -> RateLimitResult:
        opaque_subject = hash_secret(subject)[:32]
        value = self.client.eval(
            self._INCREMENT_SCRIPT,
            1,
            f"msg:ratelimit:{opaque_subject}",
            window_seconds,
        )
        count = int(value)
        return RateLimitResult(count=count, limit=limit, remaining=max(0, limit - count))


def build_rate_limit_store(url: str) -> RateLimitStore:
    try:
        client = Redis.from_url(
            url,
            decode_responses=True,
            socket_connect_timeout=1,
            socket_timeout=1,
        )
        client.ping()
        return RedisRateLimitStore(client)
    except RedisError as exc:
        if is_production():
            raise RuntimeError("Redis is required in production; refusing in-memory rate-limit fallback.") from exc
        return InMemoryRateLimitStore()
