from __future__ import annotations

import ast

from securepy.analysis.helpers import full_name
from securepy.analysis.taint import ModuleAnalysis
from securepy.models.enums import Confidence, Severity
from securepy.models.finding import Finding
from securepy.rules.base import BaseRule
from securepy.utils.snippets import line_snippet


class InsecureTempfileRule(BaseRule):
    rule_id = "INSECURE_TEMPFILE"
    title = "Insecure temporary file usage"

    def run(self, analysis: ModuleAnalysis) -> list[Finding]:
        findings: list[Finding] = []

        if analysis.module.tree is None:
            return findings

        for node in ast.walk(analysis.module.tree):
            if not isinstance(node, ast.Call):
                continue

            name = analysis.aliases.get(full_name(node.func) or "", full_name(node.func) or "")
            if name != "tempfile.mktemp":
                continue

            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    message="tempfile.mktemp() is insecure because it creates predictable names without opening securely.",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    cwe="CWE-377",
                    file_path=str(analysis.module.path),
                    line=getattr(node, "lineno", 1),
                    code_snippet=line_snippet(analysis.module.code, getattr(node, "lineno", 1)),
                    source=None,
                    sink=name,
                    trace=[],
                    remediation="Use tempfile.NamedTemporaryFile(delete=False) or tempfile.mkstemp().",
                )
            )

        return findings