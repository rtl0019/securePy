from __future__ import annotations

import ast
import re

from securepy.analysis.helpers import full_name
from securepy.analysis.taint import ModuleAnalysis
from securepy.models.enums import Confidence, Severity
from securepy.models.finding import Finding
from securepy.rules.base import BaseRule
from securepy.utils.snippets import line_snippet

SENSITIVE_NAME_RE = re.compile(r"(?i)(token|secret|session|password|reset|auth)")


class WeakCryptoRule(BaseRule):
    rule_id = "WEAK_CRYPTO"
    title = "Weak cryptography / insecure randomness"

    def run(self, analysis: ModuleAnalysis) -> list[Finding]:
        findings: list[Finding] = []

        if analysis.module.tree is None:
            return findings

        for node in ast.walk(analysis.module.tree):
            if not isinstance(node, ast.Call):
                continue

            name = analysis.aliases.get(full_name(node.func) or "", full_name(node.func) or "")

            if name in {"hashlib.md5", "hashlib.sha1"}:
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        title=self.title,
                        message=f"{name} is weak for security-sensitive hashing.",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        cwe="CWE-327",
                        file_path=str(analysis.module.path),
                        line=getattr(node, "lineno", 1),
                        code_snippet=line_snippet(analysis.module.code, getattr(node, "lineno", 1)),
                        source=None,
                        sink=name,
                        trace=[],
                        remediation="Use hashlib.sha256 or stronger algorithms when security matters.",
                    )
                )

            if name in {"random.random", "random.randint", "random.choice", "random.randrange"}:
                parent_line = line_snippet(analysis.module.code, getattr(node, "lineno", 1)).lower()
                sensitive_context = bool(SENSITIVE_NAME_RE.search(parent_line))
                if not sensitive_context:
                    continue

                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        title=self.title,
                        message="random module is not suitable for generating secrets, tokens, or session identifiers.",
                        severity=Severity.HIGH,
                        confidence=Confidence.MEDIUM,
                        cwe="CWE-338",
                        file_path=str(analysis.module.path),
                        line=getattr(node, "lineno", 1),
                        code_snippet=line_snippet(analysis.module.code, getattr(node, "lineno", 1)),
                        source=None,
                        sink=name,
                        trace=[],
                        remediation="Use the secrets module for security-sensitive randomness.",
                    )
                )

        return findings