from __future__ import annotations

import json
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any


class JsonReporter:
    def _normalize(self, value: Any) -> Any:
        if is_dataclass(value):
            return {k: self._normalize(v) for k, v in asdict(value).items()}

        if isinstance(value, Path):
            return str(value)

        if isinstance(value, dict):
            return {str(k): self._normalize(v) for k, v in value.items()}

        if isinstance(value, (list, tuple, set)):
            return [self._normalize(v) for v in value]

        if hasattr(value, "value"):  # enums
            return value.value

        return value

    def to_dict(self, result: Any) -> dict[str, Any]:
        normalized = self._normalize(result)
        if isinstance(normalized, dict):
            return normalized
        return {"results": normalized}

    def to_json(self, result: Any) -> str:
        return json.dumps(self.to_dict(result), indent=2)

    def write(self, result: Any, path: Path) -> None:
        path.write_text(self.to_json(result), encoding="utf-8")