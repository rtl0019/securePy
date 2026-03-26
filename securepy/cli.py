from __future__ import annotations

import argparse
from pathlib import Path
from typing import Sequence

from securepy.models.enums import Confidence, Severity
from securepy.reporting.console_reporter import ConsoleReporter
from securepy.reporting.json_reporter import JsonReporter
from securepy.scanner.orchestrator import ScanConfig, SecurePyOrchestrator


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="securepy", description="Local static security analyzer for Python"
    )
    subparsers = parser.add_subparsers(dest="command")

    scan = subparsers.add_parser("scan", help="Scan a project path")
    scan.add_argument("path", help="Path to project/file to scan")
    scan.add_argument(
        "--include-ext",
        nargs="*",
        default=[".py"],
        help="Included extensions",
    )
    scan.add_argument(
        "--exclude-dirs",
        nargs="*",
        default=[".git", ".venv", "venv", "__pycache__", ".pytest_cache"],
        help="Directories to exclude",
    )
    scan.add_argument(
        "--format",
        choices=["console", "json", "both"],
        default="both",
        help="Output format",
    )
    scan.add_argument("--out", default=None, help="Output JSON file path")
    scan.add_argument(
        "--min-severity",
        choices=[s.value for s in Severity],
        default="low",
        help="Minimum severity to report",
    )
    scan.add_argument(
        "--min-confidence",
        choices=[c.value for c in Confidence],
        default="low",
        help="Minimum confidence to report",
    )
    scan.add_argument(
        "--rules",
        nargs="*",
        default=None,
        help="Optional rule IDs to enable",
    )
    scan.add_argument("--no-color", action="store_true", help="Disable color in console output")
    scan.add_argument(
    "--stdout",
    action="store_true",
    help="Print JSON output to stdout instead of writing a file",
)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command != "scan":
        parser.print_help()
        return 1

    config = ScanConfig(
        root=Path(args.path),
        include_ext=set(args.include_ext),
        exclude_dirs=set(args.exclude_dirs),
        min_severity=Severity(args.min_severity),
        min_confidence=Confidence(args.min_confidence),
        enabled_rules=set(args.rules) if args.rules else None,
        no_color=bool(args.no_color),
    )

    result = SecurePyOrchestrator(config).run()

    if args.format in {"console", "both"}:
        ConsoleReporter(no_color=args.no_color).render(result)

    if args.format in {"json", "both"}:
        reporter = JsonReporter()

        if args.stdout:
            print(reporter.to_json(result))
        else:
            output_path = Path(args.out) if args.out else Path("securepy-report.json")
            reporter.write(result, output_path)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
