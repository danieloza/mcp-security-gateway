from __future__ import annotations

import json
from dataclasses import asdict
from typing import Any

from mcp_security_gateway.models import ToolManifest
from mcp_security_gateway.security import digest_json


def manifest_payload(
    *,
    mcp_server_id: str,
    name: str,
    description: str,
    required_scope: str,
    risk_level: str,
    input_schema: dict[str, Any],
    annotations: dict[str, Any],
) -> dict[str, Any]:
    return {
        "mcp_server_id": mcp_server_id,
        "name": name,
        "description": description,
        "required_scope": required_scope,
        "risk_level": risk_level,
        "input_schema": input_schema,
        "annotations": annotations,
    }


def compute_manifest_digest(payload: dict[str, Any]) -> str:
    return digest_json(payload)


def manifest_as_protocol_tool(manifest: ToolManifest) -> dict[str, Any]:
    return {
        "name": manifest.name,
        "description": manifest.description,
        "inputSchema": json.loads(manifest.input_schema),
        "annotations": json.loads(manifest.annotations),
        "_meta": {
            "gateway/toolId": manifest.id,
            "gateway/serverId": manifest.mcp_server_id,
            "gateway/requiredScope": manifest.required_scope,
            "gateway/riskLevel": manifest.risk_level,
            "gateway/manifestDigest": manifest.manifest_digest,
            "gateway/trustStatus": manifest.trust_status,
        },
    }


def verify_candidate(manifest: ToolManifest, candidate: dict[str, Any]) -> dict[str, Any]:
    expected_payload = manifest_payload(
        mcp_server_id=manifest.mcp_server_id,
        name=manifest.name,
        description=manifest.description,
        required_scope=manifest.required_scope,
        risk_level=manifest.risk_level,
        input_schema=json.loads(manifest.input_schema),
        annotations=json.loads(manifest.annotations),
    )
    candidate_payload = manifest_payload(
        mcp_server_id=manifest.mcp_server_id,
        name=str(candidate["name"]),
        description=str(candidate["description"]),
        required_scope=manifest.required_scope,
        risk_level=manifest.risk_level,
        input_schema=dict(candidate["input_schema"]),
        annotations=dict(candidate["annotations"]),
    )
    candidate_digest = compute_manifest_digest(candidate_payload)
    changed_fields = [
        field
        for field in ("name", "description", "input_schema", "annotations")
        if expected_payload[field] != candidate_payload[field]
    ]
    return {
        "tool_id": manifest.id,
        "status": "verified" if candidate_digest == manifest.manifest_digest else "drift_detected",
        "expected_digest": manifest.manifest_digest,
        "candidate_digest": candidate_digest,
        "changed_fields": changed_fields,
        "quarantine_recommended": bool(changed_fields),
    }


def validate_arguments(manifest: ToolManifest, arguments: dict[str, Any]) -> None:
    schema = json.loads(manifest.input_schema)
    properties = schema.get("properties", {})
    required = set(schema.get("required", []))
    missing = sorted(required - arguments.keys())
    if missing:
        raise ValueError(f"Missing required tool arguments: {', '.join(missing)}.")
    if schema.get("additionalProperties") is False:
        extra = sorted(arguments.keys() - properties.keys())
        if extra:
            raise ValueError(f"Unexpected tool arguments: {', '.join(extra)}.")

    for key, value in arguments.items():
        rule = properties.get(key, {})
        expected_type = rule.get("type")
        if expected_type == "string":
            if not isinstance(value, str):
                raise ValueError(f"Tool argument '{key}' must be a string.")
            if len(value) < int(rule.get("minLength", 0)):
                raise ValueError(f"Tool argument '{key}' is too short.")
            if len(value) > int(rule.get("maxLength", 100_000)):
                raise ValueError(f"Tool argument '{key}' is too long.")
        elif expected_type == "integer" and (not isinstance(value, int) or isinstance(value, bool)):
            raise ValueError(f"Tool argument '{key}' must be an integer.")
        elif expected_type == "boolean" and not isinstance(value, bool):
            raise ValueError(f"Tool argument '{key}' must be a boolean.")


def public_manifest(manifest: ToolManifest) -> dict[str, Any]:
    payload = asdict(manifest)
    payload["input_schema"] = json.loads(manifest.input_schema)
    payload["annotations"] = json.loads(manifest.annotations)
    return payload
