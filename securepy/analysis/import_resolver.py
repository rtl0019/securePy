from __future__ import annotations

import ast

from securepy.scanner.project_index import ProjectIndex
from securepy.scanner.parser import ParsedModule


class ImportResolver:
    def __init__(self, index: ProjectIndex, module: ParsedModule) -> None:
        self.index = index
        self.module = module

    def resolve_aliases(self) -> dict[str, str]:
        aliases: dict[str, str] = {}
        if self.module.tree is None:
            return aliases

        for node in ast.walk(self.module.tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    aliases[alias.asname or alias.name] = alias.name

            elif isinstance(node, ast.ImportFrom):
                mod = node.module or ""
                for alias in node.names:
                    if alias.name == "*":
                        continue
                    aliases[alias.asname or alias.name] = f"{mod}.{alias.name}" if mod else alias.name

        return aliases

    def resolve_call_target(self, name: str, local_aliases: dict[str, str]) -> str:
        parts = name.split(".")
        if not parts:
            return name

        head = parts[0]
        if head in local_aliases:
            return ".".join([local_aliases[head], *parts[1:]])
        return name