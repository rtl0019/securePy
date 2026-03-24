from __future__ import annotations

import ast

from securepy.analysis.helpers import full_name
from securepy.analysis.taint import ModuleAnalysis
from securepy.models.enums import Confidence, Severity
from securepy.models.finding import Finding
from securepy.rules.base import BaseRule
from securepy.utils.snippets import line_snippet


class UnsafeDeserializationRule(BaseRule):
    rule_id = "UNSAFE_DESERIALIZATION"
    title = "Unsafe deserialization"

    def run(self, analysis: ModuleAnalysis) -> list[Finding]:
        findings: list[Finding] = []

        for hit in analysis.sink_hits:
            if hit.sink_type not in {"pickle.load", "pickle.loads"}:
                continue

            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    message="pickle deserialization can execute attacker-controlled payloads, especially with untrusted input.",
                    severity=Severity.CRITICAL if hit.arg_tainted else Severity.HIGH,
                    confidence=Confidence.HIGH,
                    cwe="CWE-502",
                    file_path=hit.file_path,
                    line=hit.line,
                    code_snippet=line_snippet(analysis.module.code, hit.line),
                    source=hit.trace[0].label if hit.trace else None,
                    sink=hit.sink_name,
                    trace=hit.trace,
                    remediation="Avoid pickle for untrusted data. Use safer formats like JSON or strictly validated serializers.",
                )
            )

        if analysis.module.tree is None:
            return findings

        for node in ast.walk(analysis.module.tree):
            if not isinstance(node, ast.Call):
                continue

            name = analysis.aliases.get(full_name(node.func) or "", full_name(node.func) or "")
            if name != "yaml.load":
                continue

            safe_loader = any(
                kw.arg == "Loader"
                and (
                    (isinstance(kw.value, ast.Attribute) and kw.value.attr == "SafeLoader")
                    or (isinstance(kw.value, ast.Name) and kw.value.id == "SafeLoader")
                )
                for kw in node.keywords
            )

            if safe_loader:
                continue

            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    message="yaml.load() without SafeLoader may deserialize unsafe objects.",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    cwe="CWE-502",
                    file_path=str(analysis.module.path),
                    line=getattr(node, "lineno", 1),
                    code_snippet=line_snippet(analysis.module.code, getattr(node, "lineno", 1)),
                    source=None,
                    sink="yaml.load",
                    trace=[],
                    remediation="Use yaml.safe_load() or yaml.load(..., Loader=yaml.SafeLoader).",
                )
            )

        return findings