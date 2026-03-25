from __future__ import annotations


USERS = [
    ("usr_ops", "Daniel Operator", "operator", "org_danex", "msg-ops-demo"),
    ("usr_security", "Sandra Security", "security_admin", "org_danex", "msg-security-demo"),
    ("usr_platform", "Pat Platform", "platform_admin", "org_danex", "msg-platform-demo"),
]

MCP_SERVERS = [
    ("mcp_docs", "Documentation MCP", "internal", "low", "docs:read"),
    ("mcp_github", "GitHub Write MCP", "internal", "high", "repo:read,repo:write"),
    ("mcp_prod_ops", "Production Ops MCP", "production", "critical", "ops:read,ops:admin"),
]

POLICIES = [
    ("pol_default_allow", "Default Guardrails", "allow", "Allows low-risk reads inside allowed scopes."),
    ("pol_approval_gate", "Approval Gate", "approval", "Routes risky writes and elevated scopes to approval."),
    ("pol_hard_block", "Hard Block", "block", "Blocks privileged production actions and policy violations."),
]
