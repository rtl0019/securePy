from __future__ import annotations

from securepy.analysis.taint import ModuleAnalysis
from securepy.models.enums import Confidence, Severity
from securepy.models.finding import Finding
from securepy.rules.base import BaseRule
from securepy.utils.snippets import line_snippet


class PathTraversalRule(BaseRule):
    rule_id = "PATH_TRAVERSAL"
    title = "Potential path traversal"

    def run(self, analysis: ModuleAnalysis) -> list[Finding]:
        findings: list[Finding] = []

        for hit in analysis.sink_hits:
            if hit.sink_type != "path.open":
                continue
            if not hit.arg_tainted:
                continue

            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    message="Tainted input reaches file open path. Missing path normalization or allowlisting may enable path traversal.",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    cwe="CWE-22",
                    file_path=hit.file_path,
                    line=hit.line,
                    code_snippet=line_snippet(analysis.module.code, hit.line),
                    source=hit.trace[0].label if hit.trace else None,
                    sink=hit.sink_name,
                    trace=hit.trace,
                    remediation="Normalize, constrain, and validate file paths before reading or writing. Prefer allowlisted base directories.",
                )
            )

        return findings