from __future__ import annotations

import ast

from securepy.analysis.helpers import full_name
from securepy.analysis.taint import ModuleAnalysis
from securepy.models.enums import Confidence, Severity
from securepy.models.finding import Finding
from securepy.rules.base import BaseRule
from securepy.utils.snippets import line_snippet


class DebugModeRiskRule(BaseRule):
    rule_id = "DEBUG_MODE_RISK"
    title = "Debug mode risk"

    def run(self, analysis: ModuleAnalysis) -> list[Finding]:
        findings: list[Finding] = []

        if analysis.module.tree is None:
            return findings

        for node in ast.walk(analysis.module.tree):
            if not isinstance(node, ast.Call):
                continue

            name = analysis.aliases.get(full_name(node.func) or "", full_name(node.func) or "")
            if name not in {"app.run", "flask.Flask.run"}:
                continue

            for kw in node.keywords:
                if kw.arg == "debug" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            title=self.title,
                            message="Application appears to run with debug=True, which can expose sensitive internals in production.",
                            severity=Severity.MEDIUM,
                            confidence=Confidence.HIGH,
                            cwe="CWE-489",
                            file_path=str(analysis.module.path),
                            line=getattr(node, "lineno", 1),
                            code_snippet=line_snippet(analysis.module.code, getattr(node, "lineno", 1)),
                            source=None,
                            sink=name,
                            trace=[],
                            remediation="Disable debug mode in production and use environment-based configuration.",
                        )
                    )

        return findings