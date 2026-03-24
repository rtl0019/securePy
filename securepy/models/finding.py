from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from securepy.models.enums import Confidence, Severity
from securepy.models.trace import TraceStep


@dataclass(slots=True)
class Finding:
    rule_id: str
    title: str
    message: str
    severity: Severity
    confidence: Confidence
    cwe: str | None
    file_path: str
    line: int
    column: int | None = None
    code_snippet: str | None = None
    source: str | None = None
    sink: str | None = None
    trace: list[TraceStep] = field(default_factory=list)
    remediation: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.value
        data["confidence"] = self.confidence.value
        data["trace"] = [step.to_dict() for step in self.trace]
        return data


@dataclass(slots=True)
class ScanResult:
    root: str
    files_scanned: int
    parsed_files: int
    skipped_files: int
    findings: list[Finding]
    parse_errors: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "root": self.root,
            "files_scanned": self.files_scanned,
            "parsed_files": self.parsed_files,
            "skipped_files": self.skipped_files,
            "findings": [finding.to_dict() for finding in self.findings],
            "parse_errors": self.parse_errors,
        }