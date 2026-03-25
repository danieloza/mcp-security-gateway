from __future__ import annotations

import os
from pathlib import Path


def database_url() -> str:
    value = os.getenv("MSG_DATABASE_URL", "sqlite:///data/mcp_security_gateway.db")
    if value.startswith("sqlite:///"):
        relative = value.removeprefix("sqlite:///")
        return f"sqlite:///{Path(relative).resolve()}"
    return value


def redis_url() -> str:
    return os.getenv("MSG_REDIS_URL", "redis://localhost:6379/0")
