from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from . import __version__
from .baseline import apply_baseline, write_baseline
from .config import load_config
from .drift import (
    compare_ledgers,
    drift_fails,
    drift_github_output,
    drift_github_summary,
    drift_json_report,
    drift_text_report,
    load_ledger,
)
from .models import Severity
from .reporters import (
    github_output_report,
    github_report,
    github_summary,
    html_report,
    json_report,
    ledger_payload,
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
    parser.add_argument(
        "--ledger-output",
        type=Path,
        help="write a deterministic claim-and-evidence ledger as JSON",
    )
    parser.add_argument(
        "--html-output",
        type=Path,
        help="write a self-contained interactive evidence map",
    )
    parser.add_argument(
        "--compare-ledger",
        type=Path,
        help="compare the current evidence ledger with a previous ledger",
    )
    parser.add_argument(
        "--drift-output",
        type=Path,
        help="write a deterministic evidence-drift receipt as JSON",
    )
    parser.add_argument(
        "--fail-on-drift",
        choices=("none", "review", "any"),
        default="none",
        help="fail on review-requiring drift, any drift, or never fail (default: none)",
    )
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
    drift_payload = None
    current_ledger = None
    try:
        root = (args.root or Path.cwd()).resolve()
        if args.write_baseline and (
            args.compare_ledger or args.drift_output or args.fail_on_drift != "none"
        ):
            raise ValueError("--write-baseline cannot be combined with evidence-drift options")
        if not args.compare_ledger and (
            args.drift_output or args.fail_on_drift != "none"
        ):
            raise ValueError("--drift-output and --fail-on-drift require --compare-ledger")
        _validate_drift_paths(args, root)
        config_path = _rooted(args.config, root)
        config = load_config(config_path, root)
        if args.fail_on:
            config.fail_on = None if args.fail_on == "none" else Severity.parse(args.fail_on)
        requested = (_rooted(Path(value), root) for value in args.paths)
        result = scan_paths(
            (path for path in requested if path is not None),
            config,
            root,
            contain_to_root=args.root is not None,
        )
        if args.write_baseline:
            baseline_output = _rooted(args.write_baseline, root)
            assert baseline_output is not None
            write_baseline(result, baseline_output)
            print(f"Wrote {len(result.findings)} fingerprint(s) to {args.write_baseline}")
            return 0
        apply_baseline(result, _rooted(args.baseline, root))
        if args.compare_ledger:
            previous_ledger_path = _rooted(args.compare_ledger, root)
            assert previous_ledger_path is not None
            previous_ledger = load_ledger(previous_ledger_path)
            current_ledger = ledger_payload(result, root)
            drift_payload = compare_ledgers(previous_ledger, current_ledger)
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
        if drift_payload is not None:
            report = f"{report}\n{drift_text_report(drift_payload)}"

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
        if args.ledger_output:
            if current_ledger is None:
                current_ledger = ledger_payload(result, root)
            _write(args.ledger_output, json.dumps(current_ledger, indent=2, sort_keys=True))
        if args.html_output:
            _write(args.html_output, html_report(result, root))
        if args.drift_output:
            assert drift_payload is not None
            _write(args.drift_output, drift_json_report(drift_payload))
        if args.github_summary:
            summary = github_summary(result, root, config.fail_on)
            if drift_payload is not None:
                summary = f"{summary}\n\n{drift_github_summary(drift_payload)}"
            _append(args.github_summary, summary)
        if args.github_output:
            outputs = (
                f"{github_output_report(result, config.fail_on)}\n"
                f"{drift_github_output(drift_payload, args.fail_on_drift)}"
            )
            _append(args.github_output, outputs)
    except OSError as exc:
        parser.exit(2, f"claimfence: {exc}\n")

    scan_failed = result.fails_at(config.fail_on)
    drift_failed = (
        drift_payload is not None and drift_fails(drift_payload, args.fail_on_drift)
    )
    return int(scan_failed or drift_failed)


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


def _validate_drift_paths(args: argparse.Namespace, root: Path) -> None:
    compare_path = _rooted(args.compare_ledger, root)
    named_outputs = (
        ("--output", args.output),
        ("--json-output", args.json_output),
        ("--sarif-output", args.sarif_output),
        ("--ledger-output", args.ledger_output),
        ("--html-output", args.html_output),
        ("--drift-output", args.drift_output),
        ("--github-summary", args.github_summary),
        ("--github-output", args.github_output),
    )
    if compare_path is not None:
        for option, output_path in named_outputs:
            if output_path is not None and _same_location(compare_path, output_path):
                raise ValueError(
                    f"--compare-ledger must not share a path with {option}"
                )
    if args.drift_output is not None:
        for option, output_path in named_outputs:
            if option == "--drift-output" or output_path is None:
                continue
            if _same_location(args.drift_output, output_path):
                raise ValueError(f"--drift-output must not share a path with {option}")


def _same_location(first: Path, second: Path) -> bool:
    try:
        if first.resolve() == second.resolve():
            return True
    except (OSError, RuntimeError) as exc:
        raise ValueError("could not resolve an evidence-drift input or output path") from exc
    try:
        return first.exists() and second.exists() and first.samefile(second)
    except OSError:
        return False
