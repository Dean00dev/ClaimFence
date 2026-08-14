from __future__ import annotations

from collections import Counter
import html
import json
from pathlib import Path

from . import __version__
from .models import Finding, ScanResult, Severity
from .rules import RULE_DESCRIPTIONS


def text_report(result: ScanResult, root: Path, color: bool = False) -> str:
    lines: list[str] = []
    colors = {Severity.INFO: "36", Severity.WARNING: "33", Severity.ERROR: "31"}
    for finding in result.findings:
        path = _relative(finding.path, root)
        label = finding.severity.label()
        if color:
            label = f"\033[{colors[finding.severity]}m{label}\033[0m"
        lines.append(
            f"{path}:{finding.line}:{finding.column}: {label} {finding.rule_id} {finding.message}"
        )
        lines.append(f"  claim: {finding.claim}")
        lines.append(f"  fix:   {finding.suggestion}")
    counts = result.counts()
    lines.append(
        f"ClaimFence scanned {result.files_scanned} file(s): "
        f"{counts['error']} error(s), {counts['warning']} warning(s), {counts['info']} info"
        f"; {result.suppressed} suppressed; {result.baselined} baselined."
    )
    return "\n".join(lines)


def json_report(result: ScanResult) -> str:
    payload = {
        "tool": {"name": "ClaimFence", "version": __version__},
        "summary": {
            "files_scanned": result.files_scanned,
            "counts": result.counts(),
            "suppressed": result.suppressed,
            "baselined": result.baselined,
        },
        "findings": [finding.to_dict() for finding in result.findings],
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def github_report(result: ScanResult, root: Path) -> str:
    lines: list[str] = []
    level = {Severity.INFO: "notice", Severity.WARNING: "warning", Severity.ERROR: "error"}
    for finding in result.findings:
        path = _escape(_relative(finding.path, root))
        title = _escape(f"{finding.rule_id}: {finding.message}")
        message = _escape(f"{finding.claim} Fix: {finding.suggestion}")
        location = f"file={path},line={finding.line},col={finding.column},title={title}"
        lines.append(f"::{level[finding.severity]} {location}::{message}")
    return "\n".join(lines)


def sarif_report(result: ScanResult, root: Path) -> str:
    rules = []
    for rule_id, description in RULE_DESCRIPTIONS.items():
        rules.append({"id": rule_id, "shortDescription": {"text": description}})
    results = []
    level = {Severity.INFO: "note", Severity.WARNING: "warning", Severity.ERROR: "error"}
    for finding in result.findings:
        results.append(
            {
                "ruleId": finding.rule_id,
                "level": level[finding.severity],
                "message": {"text": f"{finding.message}. {finding.suggestion}"},
                "partialFingerprints": {"claimfence/v1": finding.fingerprint},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": _relative(finding.path, root)},
                            "region": {"startLine": finding.line, "startColumn": finding.column},
                        }
                    }
                ],
            }
        )
    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "ClaimFence", "version": __version__, "rules": rules}},
                "results": results,
            }
        ],
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def github_summary(result: ScanResult, root: Path, fail_on: Severity | None) -> str:
    counts = result.counts()
    failed = result.fails_at(fail_on)
    if fail_on is None:
        status = "Completed (report-only)"
    else:
        status = "Failed" if failed else "Passed"

    lines = [
        "## ClaimFence scan",
        "",
        f"**{status}** at the `{fail_on.label() if fail_on else 'none'}` threshold.",
        "",
        "| Files | Findings | Errors | Warnings | Info | Suppressed | Baselined |",
        "| ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
        (
            f"| {result.files_scanned} | {len(result.findings)} | {counts['error']} | "
            f"{counts['warning']} | {counts['info']} | {result.suppressed} | "
            f"{result.baselined} |"
        ),
    ]

    if result.findings:
        lines.extend(["", "### Findings by rule", ""])
        by_rule = Counter(finding.rule_id for finding in result.findings)
        for rule_id, count in sorted(by_rule.items()):
            description = html.escape(RULE_DESCRIPTIONS.get(rule_id, "Finding"))
            lines.append(f"- **{rule_id}** — {count}: {description}")

        lines.extend(["", "### First findings", ""])
        for finding in result.findings[:20]:
            path = html.escape(_relative(finding.path, root), quote=True)
            message = html.escape(finding.message, quote=True)
            lines.append(
                f"- **{finding.severity.label().upper()} {finding.rule_id}** — "
                f"<code>{path}:{finding.line}:{finding.column}</code> — {message}"
            )
        if len(result.findings) > 20:
            lines.append(f"- …and {len(result.findings) - 20} more finding(s).")
    else:
        lines.extend(["", "No unbaselined findings were reported."])

    lines.extend(
        [
            "",
            (
                "> ClaimFence identifies documentation that needs review; "
                "a clean scan is not a factual audit."
            ),
        ]
    )
    return "\n".join(lines)


def github_output_report(result: ScanResult, fail_on: Severity | None) -> str:
    counts = result.counts()
    if fail_on is None:
        outcome = "report-only"
    else:
        outcome = "failed" if result.fails_at(fail_on) else "passed"
    values = {
        "files-scanned": result.files_scanned,
        "findings-count": len(result.findings),
        "error-count": counts["error"],
        "warning-count": counts["warning"],
        "info-count": counts["info"],
        "suppressed-count": result.suppressed,
        "baselined-count": result.baselined,
        "outcome": outcome,
    }
    return "\n".join(f"{name}={value}" for name, value in values.items())


def _relative(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def _escape(value: str) -> str:
    escaped = value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    return escaped.replace(":", "%3A").replace(",", "%2C")
