from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class FunctionSummary:
    qualified_name: str
    module_name: str
    file_path: str
    param_names: list[str]
    returns_tainted_from_params: set[int] = field(default_factory=set)
    sink_calls: list[dict] = field(default_factory=list)
    local_aliases: dict[str, str] = field(default_factory=dict)