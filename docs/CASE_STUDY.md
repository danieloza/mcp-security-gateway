# Case Study

## Problem

AI agents can discover MCP tools whose descriptions imply what they do, but the
agent cannot be the final authority for access. Tool metadata may change after
review, high-risk arguments may be substituted after approval, and a valid
identity may still request a scope or destination outside its operating
boundary.

## Engineering Decision

MCP Security Gateway makes tool execution conditional on five independent
controls:

1. tenant-bound workload identity;
2. a pinned tool manifest fingerprint;
3. deterministic scope, DLP, rate, and environment policy;
4. maker-checker approval bound to the exact request digest;
5. a one-time capability lease consumed immediately before execution.

Low-risk knowledge access can execute automatically. Sandboxed writes pause for
approval. Production administration, manifest drift, secret-bearing arguments,
and forbidden destinations are denied before reaching the execution adapter.

## Outcome

The project demonstrates that an MCP security boundary should control execution,
not merely label a request as safe. The operator can show the full transition
from protocol call through policy, approval, execution, and tamper-evident
evidence.

## Deliberate Boundary

The repository uses a fixed in-process adapter and SQLite so the complete
security sequence remains deterministic and free to run. It does not claim
generic remote server proxying, production identity, immutable archival, or
multi-region resilience.
