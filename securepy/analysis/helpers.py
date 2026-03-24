from __future__ import annotations

import ast
from pathlib import Path


def full_name(node: ast.AST | None) -> str | None:
    if node is None:
        return None
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = full_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return full_name(node.func)
    if isinstance(node, ast.Subscript):
        return full_name(node.value)
    return None


def is_test_like_path(path: str | Path) -> bool:
    parts = Path(path).parts
    joined = "/".join(parts).lower()
    return any(token in joined for token in ["test", "tests", "example", "examples", "sample", "demo"])


def get_node_line(node: ast.AST) -> int:
    return getattr(node, "lineno", 1)