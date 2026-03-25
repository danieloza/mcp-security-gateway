from __future__ import annotations

from collections import defaultdict

from redis import Redis
from redis.exceptions import RedisError


class RateLimitStore:
    backend_name = "memory"

    def increment(self, api_key: str) -> int:
        raise NotImplementedError


class InMemoryRateLimitStore(RateLimitStore):
    backend_name = "memory"

    def __init__(self) -> None:
        self.counts: dict[str, int] = defaultdict(int)

    def increment(self, api_key: str) -> int:
        self.counts[api_key] += 1
        return self.counts[api_key]


class RedisRateLimitStore(RateLimitStore):
    backend_name = "redis"

    def __init__(self, client: Redis) -> None:
        self.client = client

    def increment(self, api_key: str) -> int:
        value = self.client.incr(f"msg:ratelimit:{api_key}")
        self.client.expire(f"msg:ratelimit:{api_key}", 60)
        return int(value)


def build_rate_limit_store(url: str) -> RateLimitStore:
    try:
        client = Redis.from_url(url, decode_responses=True)
        client.ping()
        return RedisRateLimitStore(client)
    except RedisError:
        return InMemoryRateLimitStore()
