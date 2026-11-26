"""Tool names that a model's function-calling API accepts.

Canonical tool names keep the MCP style, such as `kb.search` or
`notes.search_notes`. Manifests, policy, approvals and the audit trail use only
canonical names. OpenAI and Azure OpenAI reject a function name outside
`^[a-zA-Z0-9_-]{1,64}$`, and some clients (n8n among them) pass MCP names to the
model unchanged, so the agent fails before it calls anything.

A client that sends `/mcp?tool_names=underscore` sees an alias on `tools/list`.
`tools/call` accepts the canonical name or the alias and resolves the alias back
to the canonical name before any policy runs.
"""

from __future__ import annotations

import hashlib
import logging
import re
from collections.abc import Iterable

FUNCTION_NAME = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")
NAME_STYLES = ("dotted", "underscore")
MAX_LENGTH = 64
_UNSAFE = re.compile(r"[^a-zA-Z0-9_-]")

log = logging.getLogger(__name__)


def wire_name(canonical: str) -> str:
    """Return the alias a model may use as a function name for `canonical`.

    Each character outside `[a-zA-Z0-9_-]` becomes `_`, so `kb.search` becomes
    `kb_search`, and a name that is already valid stays as it is. A name longer
    than 64 characters keeps its first 55 characters plus `_` and 8 hex
    characters of its SHA-256: the alias stays the same across calls and
    restarts, and two long names with a shared start get different aliases.
    """
    alias = _UNSAFE.sub("_", canonical)
    if len(alias) <= MAX_LENGTH:
        return alias
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:8]
    return f"{alias[: MAX_LENGTH - 9]}_{digest}"


def alias_map(canonical_names: Iterable[str]) -> dict[str, str]:
    """Map each alias to its canonical name.

    An alias that two tools would share is dropped for both of them. A valid
    canonical name is its own alias, so an alias that spells another tool's
    canonical name is such a shared claim too. Neither tool then appears in an
    underscore listing, and a call with that alias reaches no tool by way of the
    alias. Both remain callable by their canonical names, which are unique.
    Handing the alias to one of the two would depend on which tools exist: after
    an upstream sync, an agent's cached alias could point at a different tool.
    """
    names = sorted(set(canonical_names))
    claims: dict[str, list[str]] = {}
    for canonical in names:
        claims.setdefault(wire_name(canonical), []).append(canonical)
    aliases: dict[str, str] = {}
    for alias, owners in claims.items():
        if len(owners) > 1:
            log.warning("Tool alias %r is ambiguous (%s); no tool gets it.", alias, ", ".join(owners))
            continue
        aliases[alias] = owners[0]
    return aliases


def resolve(name: str, canonical_names: Iterable[str]) -> str:
    """Return the canonical name that `name` refers to.

    A canonical name wins over an alias. An unknown name comes back unchanged,
    so the caller reports it as an unknown tool.
    """
    names = set(canonical_names)
    if name in names:
        return name
    return alias_map(names).get(name, name)
