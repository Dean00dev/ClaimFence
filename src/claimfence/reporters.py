from __future__ import annotations

import json
from pathlib import Path

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
        "tool": {"name": "ClaimFence", "version": "0.1.0"},
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
        lines.append(
            f"::{level[finding.severity]} file={path},line={finding.line},col={finding.column},title={title}::{message}"
        )
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
                "tool": {"driver": {"name": "ClaimFence", "version": "0.1.0", "rules": rules}},
                "results": results,
            }
        ],
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def _relative(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def _escape(value: str) -> str:
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A").replace(":", "%3A").replace(",", "%2C")
