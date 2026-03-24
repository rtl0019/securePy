from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from securepy.models.function_summary import FunctionSummary
from securepy.scanner.parser import ParsedModule
from securepy.utils.paths import module_name_from_path


@dataclass(slots=True)
class ProjectIndex:
    root: Path
    modules_by_name: dict[str, ParsedModule] = field(default_factory=dict)
    paths_to_module: dict[Path, str] = field(default_factory=dict)
    function_summaries: dict[str, FunctionSummary] = field(default_factory=dict)

    def register_module(self, module: ParsedModule) -> None:
        self.modules_by_name[module.module_name] = module
        self.paths_to_module[module.path] = module.module_name

    def resolve_local_module(self, path: Path) -> str:
        return module_name_from_path(self.root, path)