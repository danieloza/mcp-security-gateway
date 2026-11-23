from __future__ import annotations

import os
from pathlib import Path


LOCAL_AUDIT_KEY = "local-demo-audit-key-not-for-production"


def database_url() -> str:
    value = os.getenv("MSG_DATABASE_URL", "sqlite:///data/mcp_security_gateway.db")
    if value.startswith("sqlite:///"):
        relative = value.removeprefix("sqlite:///")
        return f"sqlite:///{Path(relative).resolve()}"
    return value


def redis_url() -> str:
    return os.getenv("MSG_REDIS_URL", "redis://localhost:6379/0")


def environment() -> str:
    return os.getenv("MSG_ENVIRONMENT", "local").strip().lower()


def is_production() -> bool:
    return environment() == "production"


AUTH_MODES = ("static", "oauth")


def auth_mode() -> str:
    """`static`: the hashed demo keys. `oauth`: access tokens from an external server."""
    value = os.getenv("MSG_AUTH_MODE", "static").strip().lower()
    if value not in AUTH_MODES:
        raise RuntimeError(f"MSG_AUTH_MODE must be one of: {', '.join(AUTH_MODES)}.")
    if is_production() and value != "oauth":
        raise RuntimeError("Production requires MSG_AUTH_MODE=oauth; the static demo keys are public.")
    return value


def allowed_hosts() -> list[str]:
    value = os.getenv("MSG_ALLOWED_HOSTS", "127.0.0.1,localhost,testserver")
    return [item.strip() for item in value.split(",") if item.strip()]


def allowed_origins() -> set[str]:
    value = os.getenv(
        "MSG_ALLOWED_ORIGINS",
        "http://127.0.0.1:8000,http://localhost:8000",
    )
    return {item.strip().rstrip("/") for item in value.split(",") if item.strip()}


def audit_hmac_key() -> str:
    value = os.getenv("MSG_AUDIT_HMAC_KEY", LOCAL_AUDIT_KEY)
    if is_production() and value == LOCAL_AUDIT_KEY:
        raise RuntimeError("MSG_AUDIT_HMAC_KEY must be configured in production.")
    return value


def capability_lease_ttl_seconds() -> int:
    value = int(os.getenv("MSG_CAPABILITY_LEASE_TTL_SECONDS", "120"))
    return max(30, min(value, 900))


def max_request_bytes() -> int:
    value = int(os.getenv("MSG_MAX_REQUEST_BYTES", "524288"))
    return max(16_384, min(value, 2_097_152))


# The public sandbox: MSG_ENVIRONMENT=sandbox. It keeps the static demo keys and
# adds the limits in mcp_security_gateway.sandbox.


def is_sandbox() -> bool:
    return environment() == "sandbox"


def _bounded_int(name: str, default: int, low: int, high: int) -> int:
    return max(low, min(int(os.getenv(name, str(default))), high))


def sandbox_ip_limit_per_minute() -> int:
    return _bounded_int("MSG_SANDBOX_IP_LIMIT_PER_MINUTE", 120, 10, 1_000)


def sandbox_reset_seconds() -> int:
    return 60 * _bounded_int("MSG_SANDBOX_RESET_MINUTES", 60, 5, 1_440)


def sandbox_max_db_bytes() -> int:
    return _bounded_int("MSG_SANDBOX_MAX_DB_BYTES", 16 * 1024 * 1024, 256 * 1024, 64 * 1024 * 1024)


def trusted_proxy_hops() -> int:
    """How many proxies in front of the sandbox append to X-Forwarded-For."""
    return _bounded_int("MSG_TRUSTED_PROXY_HOPS", 1, 0, 5)


SANDBOX_FIXTURE_HOSTS = ("127.0.0.1", "localhost")


def sandbox_fixture_url() -> str:
    """The poisoned test server the sandbox controls. Loopback only: no egress."""
    value = os.getenv("MSG_SANDBOX_FIXTURE_URL", "http://127.0.0.1:8100").strip().rstrip("/")
    scheme, _, rest = value.partition("://")
    host = rest.split("/", 1)[0].rsplit(":", 1)[0]
    if scheme != "http" or host not in SANDBOX_FIXTURE_HOSTS:
        raise RuntimeError("MSG_SANDBOX_FIXTURE_URL must be an http:// loopback address.")
    return value
