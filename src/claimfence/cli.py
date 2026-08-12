from __future__ import annotations

import argparse
from pathlib import Path
import sys

from .baseline import apply_baseline, write_baseline
from .config import load_config
from .models import Severity
from .reporters import github_report, json_report, sarif_report, text_report
from .scanner import scan_paths


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="claimfence",
        description="Lint technical documentation for evidence-bound assurance claims.",
    )
    parser.add_argument("paths", nargs="*", default=["."], help="Markdown files or directories")
    parser.add_argument("--config", type=Path, help="TOML configuration path")
    parser.add_argument("--format", choices=("text", "json", "github", "sarif"), default="text")
    parser.add_argument("--output", type=Path, help="write the report to a file")
    parser.add_argument("--fail-on", choices=("info", "warning", "error", "none"))
    parser.add_argument("--baseline", type=Path, help="ignore fingerprints in this baseline")
    parser.add_argument("--write-baseline", type=Path, help="write current finding fingerprints and exit")
    parser.add_argument("--no-color", action="store_true", help="disable ANSI colour")
    parser.add_argument("--version", action="version", version="claimfence 0.1.0")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        config = load_config(args.config)
        if args.fail_on:
            config.fail_on = None if args.fail_on == "none" else Severity.parse(args.fail_on)
        result = scan_paths((Path(value) for value in args.paths), config)
        if args.write_baseline:
            write_baseline(result, args.write_baseline)
            print(f"Wrote {len(result.findings)} fingerprint(s) to {args.write_baseline}")
            return 0
        apply_baseline(result, args.baseline)
    except (OSError, ValueError, UnicodeError) as exc:
        parser.exit(2, f"claimfence: {exc}\n")

    root = Path.cwd()
    if args.format == "json":
        report = json_report(result)
    elif args.format == "sarif":
        report = sarif_report(result, root)
    elif args.format == "github":
        report = github_report(result, root)
    else:
        report = text_report(result, root, color=sys.stdout.isatty() and not args.no_color)

    if args.output:
        try:
            args.output.write_text(report + "\n", encoding="utf-8")
        except OSError as exc:
            parser.exit(2, f"claimfence: {exc}\n")
    elif report:
        print(report)

    if config.fail_on is None:
        return 0
    return int(any(finding.severity >= config.fail_on for finding in result.findings))
