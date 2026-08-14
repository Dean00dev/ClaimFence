from __future__ import annotations

import argparse
from pathlib import Path
import sys

from . import __version__
from .baseline import apply_baseline, write_baseline
from .config import load_config
from .models import Severity
from .reporters import (
    github_output_report,
    github_report,
    github_summary,
    json_report,
    sarif_report,
    text_report,
)
from .scanner import scan_paths


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="claimfence",
        description="Lint technical documentation for evidence-bound assurance claims.",
    )
    parser.add_argument("paths", nargs="*", default=["."], help="Markdown files or directories")
    parser.add_argument(
        "--root",
        type=Path,
        help="repository root used for relative paths and evidence-reference checks",
    )
    parser.add_argument("--config", type=Path, help="TOML configuration path")
    parser.add_argument("--format", choices=("text", "json", "github", "sarif"), default="text")
    parser.add_argument("--output", type=Path, help="write the report to a file")
    parser.add_argument("--json-output", type=Path, help="also write a JSON report to this file")
    parser.add_argument("--sarif-output", type=Path, help="also write a SARIF report to this file")
    parser.add_argument("--fail-on", choices=("info", "warning", "error", "none"))
    parser.add_argument("--baseline", type=Path, help="ignore fingerprints in this baseline")
    parser.add_argument(
        "--write-baseline",
        type=Path,
        help="write current finding fingerprints and exit",
    )
    parser.add_argument(
        "--github-summary", type=Path, help="append a Markdown summary to this file"
    )
    parser.add_argument(
        "--github-output", type=Path, help="append GitHub Action outputs to this file"
    )
    parser.add_argument("--no-color", action="store_true", help="disable ANSI colour")
    parser.add_argument("--version", action="version", version=f"claimfence {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        root = (args.root or Path.cwd()).resolve()
        config_path = _rooted(args.config, root)
        config = load_config(config_path, root)
        if args.fail_on:
            config.fail_on = None if args.fail_on == "none" else Severity.parse(args.fail_on)
        requested = (_rooted(Path(value), root) for value in args.paths)
        result = scan_paths((path for path in requested if path is not None), config, root)
        if args.write_baseline:
            baseline_output = _rooted(args.write_baseline, root)
            assert baseline_output is not None
            write_baseline(result, baseline_output)
            print(f"Wrote {len(result.findings)} fingerprint(s) to {args.write_baseline}")
            return 0
        apply_baseline(result, _rooted(args.baseline, root))
    except (OSError, ValueError, UnicodeError) as exc:
        parser.exit(2, f"claimfence: {exc}\n")

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
            _write(args.output, report)
        except OSError as exc:
            parser.exit(2, f"claimfence: {exc}\n")
    elif report:
        print(report)

    try:
        if args.json_output:
            _write(args.json_output, json_report(result))
        if args.sarif_output:
            _write(args.sarif_output, sarif_report(result, root))
        if args.github_summary:
            _append(args.github_summary, github_summary(result, root, config.fail_on))
        if args.github_output:
            _append(args.github_output, github_output_report(result, config.fail_on))
    except OSError as exc:
        parser.exit(2, f"claimfence: {exc}\n")

    return int(result.fails_at(config.fail_on))


def _append(path: Path, content: str) -> None:
    with path.open("a", encoding="utf-8", newline="\n") as stream:
        stream.write(content)
        stream.write("\n")


def _write(path: Path, content: str) -> None:
    path.write_text(content + "\n", encoding="utf-8")


def _rooted(path: Path | None, root: Path) -> Path | None:
    if path is None or path.is_absolute():
        return path
    return root / path
