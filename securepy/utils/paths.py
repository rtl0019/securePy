from __future__ import annotations

from pathlib import Path


def module_name_from_path(root: Path, path: Path) -> str:
    rel = path.relative_to(root)
    parts = list(rel.parts)

    if not parts:
        return ""

    if parts[-1].endswith(".py"):
        parts[-1] = parts[-1][:-3]

    if parts and parts[-1] == "__init__":
        parts = parts[:-1]

    return ".".join(parts)