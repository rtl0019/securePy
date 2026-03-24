from __future__ import annotations

from pathlib import Path


def discover_python_files(root: Path, include_ext: set[str], exclude_dirs: set[str]) -> list[Path]:
    if root.is_file():
        return [root] if root.suffix in include_ext else []

    results: list[Path] = []
    for path in root.rglob("*"):
        if any(part in exclude_dirs for part in path.parts):
            continue
        if path.is_file() and path.suffix in include_ext:
            results.append(path)

    return sorted(results)