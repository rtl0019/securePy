from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path


@dataclass(slots=True)
class ParsedModule:
    path: Path
    module_name: str
    code: str
    tree: ast.AST | None
    syntax_error: str | None = None


def parse_python_file(path: Path, module_name: str) -> ParsedModule:
    code = path.read_text(encoding="utf-8", errors="replace")
    try:
        tree = ast.parse(code, filename=str(path))
        return ParsedModule(
            path=path,
            module_name=module_name,
            code=code,
            tree=tree,
        )
    except SyntaxError as exc:
        return ParsedModule(
            path=path,
            module_name=module_name,
            code=code,
            tree=None,
            syntax_error=f"{exc.msg} at line {exc.lineno}:{exc.offset}",
        )