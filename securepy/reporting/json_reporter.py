from __future__ import annotations

import json
from pathlib import Path

from securepy.models.finding import ScanResult


class JsonReporter:
    def write(self, result: ScanResult, path: Path) -> None:
        path.write_text(
            json.dumps(result.to_dict(), indent=2),
            encoding="utf-8",
        )