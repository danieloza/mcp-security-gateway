"""Append a result table to the GitHub Actions run summary, when running there.

Outside GitHub Actions (no GITHUB_STEP_SUMMARY), append() does nothing.
"""

from __future__ import annotations

import os
from collections.abc import Iterable, Sequence


def _cell(value: object) -> str:
    # A pipe would end the table cell, and a newline the row.
    return str(value).replace("|", "&#124;").replace("\n", " ")


def append(title: str, intro: str, columns: Sequence[str], rows: Iterable[Sequence[object]], verdict: str) -> None:
    target = os.environ.get("GITHUB_STEP_SUMMARY")
    if not target:
        return
    lines = [f"### {title}", ""]
    if intro:
        lines += [intro, ""]
    lines.append("| " + " | ".join(columns) + " |")
    lines.append("| " + " | ".join("---" for _ in columns) + " |")
    lines += ["| " + " | ".join(_cell(value) for value in row) + " |" for row in rows]
    lines += ["", verdict, ""]
    with open(target, "a", encoding="utf-8") as summary:
        summary.write("\n".join(lines) + "\n")
