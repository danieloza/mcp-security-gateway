from __future__ import annotations


# Public demo credentials are documented in README.md. Only their SHA-256
# digests are persisted so the storage path demonstrates real key hygiene.
USERS = [
    (
        "usr_ops",
        "Daniel Operator",
        "operator",
        "org_danex",
        "0e4a016ed2c8e280747b3d046b7bce2f7f26ce801ed53b93d0875d63f91695ec",
    ),
    (
        "usr_security",
        "Sandra Security",
        "security_admin",
        "org_danex",
        "57a9d9fd2820c9bff4289c5bde81f5b54fd3e1ae075cac467000d6bc2b89c7b6",
    ),
    (
        "usr_platform",
        "Pat Platform",
        "platform_admin",
        "org_danex",
        "b5f805025d1e3b0bfdfcb12e45e1becfbd0a26f1a2baf30bacc60fe15ac4cf01",
    ),
]

MCP_SERVERS = [
    ("mcp_docs", "org_danex", "Documentation MCP", "internal", "low", "docs:read", "verified"),
    (
        "mcp_github",
        "org_danex",
        "GitHub Write MCP",
        "sandbox",
        "high",
        "repo:read,repo:write",
        "verified",
    ),
    (
        "mcp_prod_ops",
        "org_danex",
        "Production Ops MCP",
        "production",
        "critical",
        "ops:read,ops:admin",
        "verified",
    ),
]

POLICIES = [
    (
        "pol_default_allow",
        "org_danex",
        "Default Guardrails",
        "allow",
        "Allows low-risk reads inside verified scope and manifest boundaries.",
        "2026.07.24-default",
    ),
    (
        "pol_approval_gate",
        "org_danex",
        "Approval Gate",
        "approval",
        "Routes risky writes through maker-checker approval and an argument-bound lease.",
        "2026.07.24-default",
    ),
    (
        "pol_hard_block",
        "org_danex",
        "Hard Block",
        "block",
        "Blocks privileged production actions, secret egress, drift, and policy violations.",
        "2026.07.24-default",
    ),
]

TOOL_DEFINITIONS = [
    {
        "id": "tool_docs_search",
        "organization_id": "org_danex",
        "mcp_server_id": "mcp_docs",
        "name": "kb.search",
        "description": "Search the approved internal operations knowledge base.",
        "required_scope": "docs:read",
        "risk_level": "low",
        "input_schema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["query"],
            "properties": {
                "query": {"type": "string", "minLength": 2, "maxLength": 180},
            },
        },
        "annotations": {
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
    },
    {
        "id": "tool_repo_write_file",
        "organization_id": "org_danex",
        "mcp_server_id": "mcp_github",
        "name": "repo.write_file",
        "description": "Stage a file change in the isolated portfolio sandbox.",
        "required_scope": "repo:write",
        "risk_level": "high",
        "input_schema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["path", "content"],
            "properties": {
                "path": {"type": "string", "minLength": 1, "maxLength": 180},
                "content": {"type": "string", "minLength": 1, "maxLength": 8000},
            },
        },
        "annotations": {
            "readOnlyHint": False,
            "destructiveHint": True,
            "idempotentHint": False,
            "openWorldHint": False,
        },
    },
    {
        "id": "tool_ops_restart",
        "organization_id": "org_danex",
        "mcp_server_id": "mcp_prod_ops",
        "name": "ops.restart_service",
        "description": "Request a production service restart.",
        "required_scope": "ops:admin",
        "risk_level": "critical",
        "input_schema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["service"],
            "properties": {
                "service": {"type": "string", "minLength": 2, "maxLength": 80},
            },
        },
        "annotations": {
            "readOnlyHint": False,
            "destructiveHint": True,
            "idempotentHint": False,
            "openWorldHint": True,
        },
    },
]
