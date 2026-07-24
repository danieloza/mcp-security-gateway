# Guided Portfolio Demo

Target duration: 6-8 minutes.

## 1. Establish the Problem

Open the dashboard and explain:

> An MCP client can discover tools, but discovery and tool annotations are not
> authorization. This gateway decides whether the exact call may execute.

Point to the five-step control path: identity, manifest, policy, lease, evidence.

## 2. Connect the Operator

Use the public local operator fixture:

```text
msg-ops-demo
```

Emphasize that the browser holds the credential only in memory and the database
stores only its SHA-256 digest.

## 3. Run Guided Defense

Select **Run guided defense**.

Explain the four results:

1. `kb.search` is low risk, schema-valid, and manifest verified, so it executes.
2. `repo.write_file` is a sandboxed write and pauses for maker-checker approval.
3. `ops.restart_service` targets privileged production scope and is blocked.
4. the secret-bearing write is redacted, blocked, and escalated to an incident.

## 4. Demonstrate Separation of Duties

Switch to:

```text
msg-security-demo
```

Approve the pending write. Explain that approval returns a short-lived one-time
lease bound to the exact request and argument digest. The gateway stores only
the lease hash.

Switch back to the operator and execute the lease. If an argument changes, the
lease is rejected before it is consumed.

## 5. Demonstrate Tool Rug-pull Detection

Return to the security administrator. In Tool Trust, select **Simulate drift**.

Explain:

> The server changed its tool description after review. The candidate manifest
> no longer matches the pinned fingerprint, so a production workflow would
> quarantine it before the next execution.

## 6. Run Attack Lab

Run the security suite and show the five passing controls:

- manifest drift;
- approval argument tamper;
- secret exfiltration;
- metadata SSRF destination;
- plaintext credential persistence.

## 7. Close with Evidence

Open an executed request from Live Traffic and select **Evidence**.

Show:

- policy and manifest versions;
- execution result digest;
- maker/checker events;
- HMAC-linked audit events;
- verified chain status;
- final evidence-pack digest.

## Closing Narrative

> The gateway does not trust the agent, the tool description, or a previous
> approval. It verifies identity, a pinned manifest, current policy, and the
> exact arguments immediately before execution, then produces evidence of what
> actually happened.
