# API Examples

The examples use public local portfolio credentials. Do not reuse them in another
environment.

```bash
export GATEWAY=http://127.0.0.1:8000
export OPERATOR_KEY=msg-ops-demo
export SECURITY_KEY=msg-security-demo
```

## Health

```bash
curl -s "$GATEWAY/health"
```

Representative response:

```json
{
  "service": "mcp-security-gateway",
  "environment": "local",
  "database_backend": "sqlite",
  "rate_limit_backend": "redis",
  "api_key_storage": "sha256_digest_only",
  "protocol": "MCP JSON-RPC tools/list + tools/call",
  "users": 3,
  "servers": 3,
  "tools": 3,
  "requests": 0,
  "pending_approvals": 0,
  "incidents": 0,
  "executions": 0
}
```

## MCP Initialize

```bash
curl -s -X POST "$GATEWAY/mcp" \
  -H "Authorization: Bearer $OPERATOR_KEY" \
  -H "Mcp-Method: initialize" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}'
```

## List Verified Tools

```bash
curl -s -X POST "$GATEWAY/mcp" \
  -H "Authorization: Bearer $OPERATOR_KEY" \
  -H "Mcp-Method: tools/list" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'
```

## Execute a Low-risk Tool

```bash
curl -s -X POST "$GATEWAY/mcp" \
  -H "Authorization: Bearer $OPERATOR_KEY" \
  -H "Mcp-Method: tools/call" \
  -H "Mcp-Name: kb.search" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc":"2.0",
    "id":"safe-read-1",
    "method":"tools/call",
    "params":{
      "name":"kb.search",
      "arguments":{"query":"approval manifest"},
      "_meta":{
        "gateway/justification":"Retrieve the approved security runbook before execution."
      }
    }
  }'
```

The result contains `status: executed`, a request ID, execution ID, redacted
result, and result digest.

## Request a Governed Write

```bash
curl -s -X POST "$GATEWAY/mcp" \
  -H "Authorization: Bearer $OPERATOR_KEY" \
  -H "Mcp-Method: tools/call" \
  -H "Mcp-Name: repo.write_file" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc":"2.0",
    "id":"write-1",
    "method":"tools/call",
    "params":{
      "name":"repo.write_file",
      "arguments":{
        "path":"docs/review.md",
        "content":"Approved portfolio evidence."
      },
      "_meta":{
        "gateway/justification":"Stage a bounded documentation change in the isolated sandbox."
      }
    }
  }'
```

Representative result:

```json
{
  "status": "approval_required",
  "requestId": "req_random",
  "requestDigest": "sha256",
  "policyVersion": "2026.07.24-default"
}
```

## Approve the Exact Payload

```bash
curl -s -X POST "$GATEWAY/approvals/APR_ID/decision" \
  -H "Authorization: Bearer $SECURITY_KEY" \
  -H "Content-Type: application/json" \
  -d '{"decision":"approved"}'
```

The response returns the raw capability lease once. Only its digest is stored.

## Execute the Approved Request

```bash
curl -s -X POST "$GATEWAY/requests/REQUEST_ID/execute" \
  -H "Authorization: Bearer $OPERATOR_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "arguments":{
      "path":"docs/review.md",
      "content":"Approved portfolio evidence."
    },
    "capability_lease":"LEASE_RETURNED_BY_APPROVAL"
  }'
```

Changing either argument, reusing the lease, using an expired lease, or calling
from the wrong tenant is rejected.

## Run the MCP Attack Lab

```bash
curl -s -X POST "$GATEWAY/attack-lab/run" \
  -H "Authorization: Bearer $SECURITY_KEY"
```

## Export Request Evidence

```bash
curl -s "$GATEWAY/requests/REQUEST_ID/evidence" \
  -H "Authorization: Bearer $OPERATOR_KEY"
```

The evidence response contains redacted request data, approval and execution
records, the request audit timeline, full-chain verification status, and an
evidence-pack digest.
