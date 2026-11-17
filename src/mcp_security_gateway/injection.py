"""Heuristic detection of instructions aimed at the agent inside MCP tool text.

Used twice: on tool descriptions and schemas when an upstream is synced (tool
poisoning), and on tool output before it reaches the agent (indirect prompt
injection). These are patterns, not a guarantee: a determined author can phrase
an injection these rules do not know. A match withholds the text; no match only
means none of these patterns was found.
"""

from __future__ import annotations

import re
from typing import Any

# Characters that render as nothing but still reach the model: Unicode tag
# characters (used to smuggle ASCII), zero-width characters and bidi controls.
INVISIBLE = re.compile("[\U000e0000-\U000e007f\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff]")

PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "instruction_override",
        re.compile(
            r"\b(ignore|disregard|forget|override)\b[^.\n]{0,40}\b(previous|prior|above|earlier|all|any|your)\b"
            r"[^.\n]{0,30}\b(instructions?|rules|guidelines|prompts?|directions)\b",
            re.IGNORECASE,
        ),
    ),
    ("role_reassignment", re.compile(r"\b(you are now|act as|new system prompt|system prompt:)", re.IGNORECASE)),
    (
        "concealment",
        re.compile(
            r"\b(do not|don't|never)\s+(tell|inform|mention|reveal|show)\b[^.\n]{0,30}\b(user|human|operator)\b"
            r"|\bwithout (telling|informing|notifying) the (user|human)\b",
            re.IGNORECASE,
        ),
    ),
    ("hidden_block", re.compile(r"<\s*/?\s*(important|system|instructions?|secret)\s*>", re.IGNORECASE)),
    (
        "secret_file_coaxing",
        re.compile(
            r"(~|\$HOME|%USERPROFILE%)?[\\/]?\.(ssh|aws|kube|cursor|docker)[\\/]"
            r"|\bid_(rsa|ed25519)\b|(^|[\\/\s])\.env\b|\bmcp\.json\b|\bcredentials\.json\b",
            re.IGNORECASE,
        ),
    ),
    (
        "tool_redirection",
        re.compile(
            r"\b(call|invoke|use|run)\s+(the\s+)?(tool|function)\b[^.\n]{0,60}\b(before|instead|first|then)\b",
            re.IGNORECASE,
        ),
    ),
)


def text_findings(text: str) -> list[str]:
    """Names of the patterns found in one piece of text, in a stable order."""
    found = []
    if INVISIBLE.search(text):
        found.append("invisible_characters")
    found.extend(name for name, pattern in PATTERNS if pattern.search(text))
    return found


def inspect_value(value: Any) -> list[dict[str, str]]:
    """Findings for every string inside a JSON-like value, with where each was found."""
    findings: list[dict[str, str]] = []

    def walk(item: Any, path: str) -> None:
        if isinstance(item, str):
            findings.extend({"type": name, "path": path or "$"} for name in text_findings(item))
        elif isinstance(item, dict):
            for key, inner in item.items():
                walk(str(key), f"{path}.<key>")
                walk(inner, f"{path}.{key}")
        elif isinstance(item, list):
            for index, inner in enumerate(item):
                walk(inner, f"{path}[{index}]")

    walk(value, "")
    return findings
