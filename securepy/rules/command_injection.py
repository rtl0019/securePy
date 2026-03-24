from __future__ import annotations

from securepy.analysis.taint import ModuleAnalysis
from securepy.models.enums import Confidence, Severity
from securepy.models.finding import Finding
from securepy.rules.base import BaseRule
from securepy.utils.snippets import line_snippet


class CommandInjectionRule(BaseRule):
    rule_id = "COMMAND_INJECTION"
    title = "Command execution / shell injection risk"

    def run(self, analysis: ModuleAnalysis) -> list[Finding]:
        findings: list[Finding] = []

        for hit in analysis.sink_hits:
            if hit.sink_type not in {"os.system", "os.popen", "subprocess.shell"}:
                continue

            if hit.sink_type == "subprocess.shell" and hit.detail.get("arg_is_list") and not hit.arg_tainted:
                severity = Severity.MEDIUM
                confidence = Confidence.LOW
                message = "subprocess call uses shell=True. This increases command injection risk."
            elif hit.arg_tainted:
                severity = Severity.CRITICAL
                confidence = Confidence.HIGH
                message = "Tainted input reaches command execution sink."
            else:
                severity = Severity.HIGH
                confidence = Confidence.MEDIUM
                message = "Command execution API is used. Review whether untrusted input can reach it."

            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    message=message,
                    severity=severity,
                    confidence=confidence,
                    cwe="CWE-78",
                    file_path=hit.file_path,
                    line=hit.line,
                    code_snippet=line_snippet(analysis.module.code, hit.line),
                    source=hit.trace[0].label if hit.trace else None,
                    sink=hit.sink_name,
                    trace=hit.trace,
                    remediation="Prefer subprocess.run([...], shell=False). Validate or whitelist user-controlled command parts.",
                )
            )

        return findings