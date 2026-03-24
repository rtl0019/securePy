from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from securepy.analysis.interprocedural import SummaryBuilder
from securepy.analysis.taint import ModuleAnalyzer
from securepy.models.enums import CONFIDENCE_ORDER, SEVERITY_ORDER, Confidence, Severity
from securepy.models.finding import Finding, ScanResult
from securepy.rules.assert_security import AssertUsedForSecurityRule
from securepy.rules.command_injection import CommandInjectionRule
from securepy.rules.debug_mode import DebugModeRiskRule
from securepy.rules.exec_eval import ExecEvalRule
from securepy.rules.hardcoded_secret import HardcodedSecretRule
from securepy.rules.insecure_tempfile import InsecureTempfileRule
from securepy.rules.path_traversal import PathTraversalRule
from securepy.rules.sql_injection import SqlInjectionRule
from securepy.rules.unsafe_deserialization import UnsafeDeserializationRule
from securepy.rules.weak_crypto import WeakCryptoRule
from securepy.scanner.file_discovery import discover_python_files
from securepy.scanner.parser import parse_python_file
from securepy.scanner.project_index import ProjectIndex


@dataclass(slots=True)
class ScanConfig:
    root: Path
    include_ext: set[str]
    exclude_dirs: set[str]
    min_severity: Severity
    min_confidence: Confidence
    enabled_rules: set[str] | None = None
    no_color: bool = False


class SecurePyOrchestrator:
    def __init__(self, config: ScanConfig) -> None:
        self.config = config
        self.rule_classes = [
            ExecEvalRule,
            CommandInjectionRule,
            SqlInjectionRule,
            PathTraversalRule,
            HardcodedSecretRule,
            UnsafeDeserializationRule,
            WeakCryptoRule,
            InsecureTempfileRule,
            AssertUsedForSecurityRule,
            DebugModeRiskRule,
        ]

    def _enabled_rules(self):
        instances = [cls() for cls in self.rule_classes]
        if not self.config.enabled_rules:
            return instances
        return [rule for rule in instances if rule.rule_id in self.config.enabled_rules]

    def _passes_threshold(self, finding: Finding) -> bool:
        return (
            SEVERITY_ORDER[finding.severity] >= SEVERITY_ORDER[self.config.min_severity]
            and CONFIDENCE_ORDER[finding.confidence] >= CONFIDENCE_ORDER[self.config.min_confidence]
        )

    def run(self) -> ScanResult:
        files = discover_python_files(self.config.root, self.config.include_ext, self.config.exclude_dirs)
        root_path = self.config.root.resolve()
        if root_path.is_file():
            root_path = root_path.parent
        index = ProjectIndex(root=root_path)
        parse_errors: list[dict] = []
        parsed_files = 0

        for path in files:
            module_name = index.resolve_local_module(path.resolve())
            parsed = parse_python_file(path.resolve(), module_name)
            index.register_module(parsed)
            if parsed.tree is None:
                parse_errors.append({"file_path": str(path), "error": parsed.syntax_error})
            else:
                parsed_files += 1

        SummaryBuilder(index).build()

        findings: list[Finding] = []
        rules = self._enabled_rules()

        for module in index.modules_by_name.values():
            if module.tree is None:
                continue
            analyzer = ModuleAnalyzer(index=index, module=module)
            module_analysis = analyzer.analyze()
            for rule in rules:
                findings.extend(rule.run(module_analysis))

        findings = [f for f in findings if self._passes_threshold(f)]
        findings.sort(key=lambda f: (f.file_path, f.line, f.rule_id))

        return ScanResult(
            root=str(self.config.root.resolve()),
            files_scanned=len(files),
            parsed_files=parsed_files,
            skipped_files=len(files) - parsed_files,
            findings=findings,
            parse_errors=parse_errors,
        )