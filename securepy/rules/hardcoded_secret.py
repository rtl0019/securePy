from __future__ import annotations

import ast
import re

from securepy.analysis.helpers import is_test_like_path
from securepy.analysis.taint import ModuleAnalysis
from securepy.models.enums import Confidence, Severity
from securepy.models.finding import Finding
from securepy.rules.base import BaseRule
from securepy.utils.entropy import shannon_entropy
from securepy.utils.snippets import line_snippet

SECRET_NAME_RE = re.compile(
    r"(?i)(password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key)"
)
NOISY_VALUES = {"test", "dummy", "example", "changeme", "password", "secret", "token"}
AWS_KEY_RE = re.compile(r"AKIA[0-9A-Z]{16}")


class HardcodedSecretRule(BaseRule):
    rule_id = "HARD_CODED_SECRET"
    title = "Hard-coded secret candidate"

    def run(self, analysis: ModuleAnalysis) -> list[Finding]:
        findings: list[Finding] = []

        if analysis.module.tree is None:
            return findings

        noisy_path = is_test_like_path(analysis.module.path)

        for node in ast.walk(analysis.module.tree):
            if not isinstance(node, ast.Assign):
                continue
            if len(node.targets) != 1 or not isinstance(node.targets[0], ast.Name):
                continue
            if not isinstance(node.value, ast.Constant) or not isinstance(node.value.value, str):
                continue

            var_name = node.targets[0].id
            value = node.value.value.strip()

            suspicious_name = bool(SECRET_NAME_RE.search(var_name))
            high_entropy = len(value) >= 12 and shannon_entropy(value) >= 3.5
            known_shape = bool(AWS_KEY_RE.search(value))

            if not (suspicious_name or high_entropy or known_shape):
                continue

            severity = Severity.HIGH if suspicious_name or known_shape else Severity.MEDIUM
            confidence = Confidence.HIGH if known_shape else Confidence.MEDIUM

            if value.lower() in NOISY_VALUES or noisy_path:
                confidence = Confidence.LOW
                severity = Severity.LOW if noisy_path else Severity.MEDIUM

            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    message=f"String assigned to '{var_name}' looks like a hard-coded secret.",
                    severity=severity,
                    confidence=confidence,
                    cwe="CWE-798",
                    file_path=str(analysis.module.path),
                    line=getattr(node, "lineno", 1),
                    code_snippet=line_snippet(analysis.module.code, getattr(node, "lineno", 1)),
                    source=var_name,
                    sink=None,
                    trace=[],
                    remediation="Move secrets to environment variables or a secrets manager. Avoid storing real credentials in source code.",
                )
            )

        return findings