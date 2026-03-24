from __future__ import annotations

from collections import Counter

from securepy.models.finding import ScanResult


class ConsoleReporter:
    def __init__(self, no_color: bool = False) -> None:
        self.no_color = no_color

    def render(self, result: ScanResult) -> None:
        counts = Counter(f.severity.value for f in result.findings)

        print("=" * 72)
        print("SecurePy Scan Summary")
        print("=" * 72)
        print(f"Root: {result.root}")
        print(f"Files scanned: {result.files_scanned}")
        print(f"Parsed files:  {result.parsed_files}")
        print(f"Skipped files: {result.skipped_files}")
        print(f"Findings:      {len(result.findings)}")
        print(
            "Severity counts: "
            f"critical={counts.get('critical', 0)} "
            f"high={counts.get('high', 0)} "
            f"medium={counts.get('medium', 0)} "
            f"low={counts.get('low', 0)}"
        )

        if result.parse_errors:
            print(f"Parse errors:  {len(result.parse_errors)}")

        print("-" * 72)

        for finding in result.findings:
            print(
                f"[{finding.severity.value.upper():8}] "
                f"[{finding.confidence.value.upper():6}] "
                f"{finding.rule_id} {finding.file_path}:{finding.line}"
            )
            print(f"  {finding.message}")

            if finding.code_snippet:
                print(f"  > {finding.code_snippet.strip()}")

            if finding.source:
                print(f"  Source: {finding.source}")

            if finding.sink:
                print(f"  Sink: {finding.sink}")

            if finding.trace:
                trace_text = " -> ".join(step.label for step in finding.trace)
                print(f"  Trace: {trace_text}")

            if finding.cwe:
                print(f"  CWE: {finding.cwe}")

            if finding.remediation:
                print(f"  Fix: {finding.remediation}")

            print()

        if result.parse_errors:
            print("=" * 72)
            print("Parse Errors")
            print("=" * 72)
            for error in result.parse_errors:
                print(f"{error['file_path']}: {error['error']}")