from __future__ import annotations

import ast

from securepy.analysis.taint import ModuleAnalysis
from securepy.models.enums import Confidence, Severity
from securepy.models.finding import Finding
from securepy.rules.base import BaseRule
from securepy.utils.snippets import line_snippet


class SqlInjectionRule(BaseRule):
    rule_id = "SQL_INJECTION"
    title = "Potential SQL injection"

    def _query_is_dynamic(self, node: ast.AST | None) -> bool:
        if node is None:
            return False
        return isinstance(node, (ast.BinOp, ast.JoinedStr, ast.Call))

    def run(self, analysis: ModuleAnalysis) -> list[Finding]:
        findings: list[Finding] = []

        for hit in analysis.sink_hits:
            if hit.sink_type != "sql.execute":
                continue

            query_node = hit.detail.get("query_node")
            parameterized = hit.detail.get("parameterized", False)
            dynamic = self._query_is_dynamic(query_node)

            if parameterized and not hit.arg_tainted:
                continue

            if parameterized and hit.arg_tainted:
                severity = Severity.MEDIUM
                confidence = Confidence.MEDIUM
                message = (
                    "SQL execution appears parameterized, but the query itself is "
                    "dynamically influenced by tainted input."
                )
            elif hit.arg_tainted or dynamic:
                severity = Severity.HIGH
                confidence = Confidence.HIGH if hit.arg_tainted else Confidence.MEDIUM
                message = "Dynamic SQL query construction detected near execute()/executemany()."
            else:
                continue

            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    message=message,
                    severity=severity,
                    confidence=confidence,
                    cwe="CWE-89",
                    file_path=hit.file_path,
                    line=hit.line,
                    code_snippet=line_snippet(analysis.module.code, hit.line),
                    source=hit.trace[0].label if hit.trace else None,
                    sink=hit.sink_name,
                    trace=hit.trace,
                    remediation=(
                        "Use parameterized queries and avoid string concatenation, "
                        "f-strings, format(), or % formatting for SQL."
                    ),
                )
            )

        return findings