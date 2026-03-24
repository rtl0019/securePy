from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(slots=True)
class TraceStep:
    kind: str
    label: str
    file_path: str
    line: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)