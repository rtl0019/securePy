from __future__ import annotations

from securepy.analysis.taint import ModuleAnalysis
from securepy.models.enums import Confidence, Severity
from securepy.models.finding import Finding
from securepy.rules.base import BaseRule
from securepy.utils.snippets import line_snippet


class ExecEvalRule(BaseRule):
    rule_id = "EXEC_EVAL"
    title = "Dynamic code execution risk"

    def run(self, analysis: ModuleAnalysis) -> list[Finding]:
        findings: list[Finding] = []

        for hit in analysis.sink_hits:
            if hit.sink_type not in {"eval", "exec", "compile"}:
                continue

            severity = Severity.CRITICAL if hit.arg_tainted else Severity.HIGH
            confidence = Confidence.HIGH if hit.arg_tainted else Confidence.MEDIUM

            message = (
                f"Tainted input reaches {hit.sink_name}, enabling potential code execution."
                if hit.arg_tainted
                else f"Use of {hit.sink_name} is risky even with constant input."
            )

            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    message=message,
                    severity=severity,
                    confidence=confidence,
                    cwe="CWE-95",
                    file_path=hit.file_path,
                    line=hit.line,
                    code_snippet=line_snippet(analysis.module.code, hit.line),
                    source=hit.trace[0].label if hit.trace else None,
                    sink=hit.sink_name,
                    trace=hit.trace,
                    remediation="Avoid eval/exec/compile on untrusted input. Prefer explicit parsing or dispatch tables.",
                )
            )

        return findings