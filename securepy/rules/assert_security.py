from __future__ import annotations

import ast
import re

from securepy.analysis.taint import ModuleAnalysis
from securepy.models.enums import Confidence, Severity
from securepy.models.finding import Finding
from securepy.rules.base import BaseRule
from securepy.utils.snippets import line_snippet

SECURITY_ASSERT_RE = re.compile(r"(?i)(auth|token|password|admin|permission|access|is_safe|validate)")


class AssertUsedForSecurityRule(BaseRule):
    rule_id = "ASSERT_USED_FOR_SECURITY"
    title = "Assert used for security-sensitive logic"

    def run(self, analysis: ModuleAnalysis) -> list[Finding]:
        findings: list[Finding] = []

        if analysis.module.tree is None:
            return findings

        for node in ast.walk(analysis.module.tree):
            if not isinstance(node, ast.Assert):
                continue

            text = ast.unparse(node.test)
            if not SECURITY_ASSERT_RE.search(text):
                continue

            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    message="assert is used in logic that appears security-related. Assertions can be removed with Python optimization flags.",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    cwe="CWE-617",
                    file_path=str(analysis.module.path),
                    line=getattr(node, "lineno", 1),
                    code_snippet=line_snippet(analysis.module.code, getattr(node, "lineno", 1)),
                    source=None,
                    sink="assert",
                    trace=[],
                    remediation="Replace security-relevant asserts with explicit conditional checks and exceptions.",
                )
            )

        return findings