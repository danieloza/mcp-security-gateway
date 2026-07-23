from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import re
import secrets
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse


SECRET_KEY_PATTERN = re.compile(
    r"(?:^|[_-])(authorization|cookie|credential|password|secret|token|api[_-]?key)(?:$|[_-])",
    re.IGNORECASE,
)
SECRET_VALUE_PATTERN = re.compile(
    r"(?:bearer\s+[a-z0-9._~+/=-]{12,}|"
    r"(?:sk|ghp|github_pat|xox[baprs])[-_][a-z0-9_-]{12,}|"
    r"-----BEGIN [A-Z ]+PRIVATE KEY-----)",
    re.IGNORECASE,
)
URL_KEY_PATTERN = re.compile(r"(?:^|[_-])(url|uri|endpoint|callback|webhook)(?:$|[_-])", re.IGNORECASE)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def utc_now_iso() -> str:
    return utc_now().isoformat().replace("+00:00", "Z")


def parse_utc(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def new_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_hex(12)}"


def hash_secret(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def constant_time_equal(left: str, right: str) -> bool:
    return hmac.compare_digest(left.encode("ascii"), right.encode("ascii"))


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def request_digest(
    *,
    organization_id: str,
    requested_by: str,
    server_id: str,
    tool_name: str,
    requested_scope: str,
    arguments_digest: str,
    manifest_digest: str,
    policy_version: str,
) -> str:
    return digest_json(
        {
            "organization_id": organization_id,
            "requested_by": requested_by,
            "server_id": server_id,
            "tool_name": tool_name,
            "requested_scope": requested_scope,
            "arguments_digest": arguments_digest,
            "manifest_digest": manifest_digest,
            "policy_version": policy_version,
        }
    )


def audit_event_digest(
    *,
    key: str,
    previous_digest: str,
    organization_id: str,
    event_type: str,
    subject_id: str,
    actor_id: str,
    payload_json: str,
    created_at: str,
) -> str:
    message = canonical_json(
        {
            "previous_digest": previous_digest,
            "organization_id": organization_id,
            "event_type": event_type,
            "subject_id": subject_id,
            "actor_id": actor_id,
            "payload_json": payload_json,
            "created_at": created_at,
        }
    )
    return hmac.new(key.encode("utf-8"), message.encode("utf-8"), hashlib.sha256).hexdigest()


def redact_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: "[REDACTED]" if SECRET_KEY_PATTERN.search(str(key)) else redact_value(inner)
            for key, inner in value.items()
        }
    if isinstance(value, list):
        return [redact_value(item) for item in value]
    if isinstance(value, str) and SECRET_VALUE_PATTERN.search(value):
        return "[REDACTED]"
    return value


def security_findings(arguments: dict[str, Any]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []

    def inspect(value: Any, path: str) -> None:
        if isinstance(value, dict):
            for key, inner in value.items():
                child_path = f"{path}.{key}" if path else str(key)
                if SECRET_KEY_PATTERN.search(str(key)):
                    findings.append(
                        {
                            "type": "secret_field",
                            "path": child_path,
                            "severity": "high",
                        }
                    )
                if URL_KEY_PATTERN.search(str(key)) and isinstance(inner, str) and is_forbidden_destination(inner):
                    findings.append(
                        {
                            "type": "forbidden_destination",
                            "path": child_path,
                            "severity": "critical",
                        }
                    )
                inspect(inner, child_path)
        elif isinstance(value, list):
            for index, item in enumerate(value):
                inspect(item, f"{path}[{index}]")
        elif isinstance(value, str) and SECRET_VALUE_PATTERN.search(value):
            findings.append(
                {
                    "type": "secret_value",
                    "path": path or "$",
                    "severity": "high",
                }
            )

    inspect(arguments, "")
    return findings


def is_forbidden_destination(value: str) -> bool:
    try:
        parsed = urlparse(value)
    except ValueError:
        return True
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return True

    hostname = parsed.hostname.rstrip(".").lower()
    if hostname in {"localhost", "metadata.google.internal"} or hostname.endswith(".local"):
        return True
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        return False
    return any(
        (
            address.is_private,
            address.is_loopback,
            address.is_link_local,
            address.is_multicast,
            address.is_reserved,
            address.is_unspecified,
        )
    )
