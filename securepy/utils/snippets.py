from __future__ import annotations


def line_snippet(code: str, line_no: int) -> str | None:
    lines = code.splitlines()
    if 1 <= line_no <= len(lines):
        return lines[line_no - 1]
    return None