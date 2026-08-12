from __future__ import annotations

import fnmatch
import hashlib
from pathlib import Path
import re
from typing import Iterable

from .config import Config
from .models import Finding, ScanResult, Severity
from .rules import (
    EVIDENCE_PATTERNS,
    LIMITATION_PATTERN,
    RULES,
    SCOPE_PATTERN,
    SECTION_PATTERN,
    SUPPRESSION_PATTERN,
)


MARKDOWN_SUFFIXES = {".md", ".mdx", ".markdown"}


def scan_paths(paths: Iterable[Path], config: Config) -> ScanResult:
    result = ScanResult()
    requested = list(paths)
    missing = [path for path in requested if not path.exists()]
    if missing:
        raise FileNotFoundError(f"path not found: {missing[0]}")
    for path in _discover(requested, config.exclude):
        result.files_scanned += 1
        file_findings, suppressed = scan_file(path, config)
        result.findings.extend(file_findings)
        result.suppressed += suppressed
    result.findings.sort(key=lambda finding: (finding.path.as_posix(), finding.line, finding.rule_id))
    return result


def scan_file(path: Path, config: Config) -> tuple[list[Finding], int]:
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()
    prose = _prose_mask(lines)
    suppression_map = _suppressions(lines)
    headings = [match.group(1).strip().lower() for line in prose if (match := SECTION_PATTERN.match(line))]
    findings: list[Finding] = []
    suppressed = 0
    assurance_lines: list[int] = []

    for index, line in enumerate(prose):
        if not line:
            continue
        for rule in RULES:
            if rule.rule_id in config.disabled_rules:
                continue
            for match in rule.pattern.finditer(line):
                if _is_negated(line, match.start()):
                    continue
                context = _context(prose, index, config.context_lines)
                present = _context_types(context, config.extra_evidence_terms)
                if rule.required_context.issubset(present):
                    continue
                if rule.rule_id in suppression_map.get(index + 1, set()) or "ALL" in suppression_map.get(index + 1, set()):
                    suppressed += 1
                    continue
                claim = line.strip()
                findings.append(
                    _finding(
                        rule.rule_id,
                        rule.severity,
                        path,
                        index + 1,
                        match.start() + 1,
                        rule.message,
                        claim,
                        rule.suggestion,
                    )
                )
                if rule.rule_id in {"CF001", "CF002", "CF003"}:
                    assurance_lines.append(index + 1)
                break

    if assurance_lines:
        if "CF101" not in config.disabled_rules and not any(
            re.search(r"\b(?:limitations?|boundaries|non-goals?|what\s+it\s+does\s+not)\b", heading, re.I)
            for heading in headings
        ):
            findings.append(
                _finding(
                    "CF101",
                    Severity.WARNING,
                    path,
                    assurance_lines[0],
                    1,
                    "assurance claims appear in a document with no limitations section",
                    lines[assurance_lines[0] - 1].strip(),
                    "Add a clearly titled limitations, boundaries, non-goals, or 'what this does not establish' section.",
                )
            )
        if "CF102" not in config.disabled_rules and not any(
            re.search(r"\b(?:verify|verification|reproduc|testing|evidence)\b", heading, re.I)
            for heading in headings
        ):
            findings.append(
                _finding(
                    "CF102",
                    Severity.WARNING,
                    path,
                    assurance_lines[0],
                    1,
                    "assurance claims appear in a document with no verification section",
                    lines[assurance_lines[0] - 1].strip(),
                    "Add a verification or reproduction section with exact commands and expected evidence.",
                )
            )
    return findings, suppressed


def _discover(paths: Iterable[Path], excludes: list[str]) -> list[Path]:
    discovered: set[Path] = set()
    for raw in paths:
        path = raw.resolve()
        if path.is_file() and path.suffix.lower() in MARKDOWN_SUFFIXES:
            discovered.add(path)
        elif path.is_dir():
            for candidate in path.rglob("*"):
                if not candidate.is_file() or candidate.suffix.lower() not in MARKDOWN_SUFFIXES:
                    continue
                relative = candidate.relative_to(path).as_posix()
                if any(fnmatch.fnmatch(relative, pattern) for pattern in excludes):
                    continue
                discovered.add(candidate.resolve())
    return sorted(discovered)


def _prose_mask(lines: list[str]) -> list[str]:
    masked: list[str] = []
    fence: str | None = None
    in_comment = False
    for line in lines:
        fence_match = re.match(r"^\s{0,3}(`{3,}|~{3,})", line)
        if fence_match:
            marker = fence_match.group(1)[0]
            fence = None if fence == marker else marker if fence is None else fence
            masked.append("")
            continue
        if fence is not None:
            masked.append("")
            continue
        if in_comment:
            if "-->" in line:
                in_comment = False
            masked.append("")
            continue
        if "<!--" in line:
            before, _, after = line.partition("<!--")
            if "-->" not in after:
                in_comment = True
            line = before
        without_inline_code = re.sub(r"`[^`]*`", "", line)
        masked.append(without_inline_code)
    return masked


def _suppressions(lines: list[str]) -> dict[int, set[str]]:
    result: dict[int, set[str]] = {}
    for index, line in enumerate(lines):
        match = SUPPRESSION_PATTERN.search(line)
        if not match:
            continue
        rules = {value.strip().upper() for value in match.group(1).split(",")}
        result[index + 2] = rules
    return result


def _context(lines: list[str], index: int, radius: int) -> str:
    start = max(0, index - radius)
    end = min(len(lines), index + radius + 1)
    return "\n".join(line for line in lines[start:end] if line)


def _context_types(context: str, extra_evidence_terms: list[str]) -> set[str]:
    result: set[str] = set()
    if any(pattern.search(context) for pattern in EVIDENCE_PATTERNS) or any(
        term.lower() in context.lower() for term in extra_evidence_terms
    ):
        result.add("evidence")
    if SCOPE_PATTERN.search(context):
        result.add("scope")
    if LIMITATION_PATTERN.search(context):
        result.add("limitation")
    return result


def _is_negated(line: str, start: int) -> bool:
    prefix = line[max(0, start - 120):start]
    immediate = re.search(
        r"\b(?:not|never|isn['’]?t|aren['’]?t|doesn['’]?t|cannot|can['’]?t)\s+$",
        prefix,
        re.I,
    )
    epistemic = re.search(
        r"\b(?:cannot|can['’]?t|does\s+not|doesn['’]?t)\s+"
        r"(?:determine|establish|verify|confirm|claim|show|prove|mean)\b[^.!?;]{0,90}$",
        prefix,
        re.I,
    )
    no_evidence = re.search(r"\bno\s+evidence\b[^.!?;]{0,90}$", prefix, re.I)
    return bool(immediate or epistemic or no_evidence)


def _finding(
    rule_id: str,
    severity: Severity,
    path: Path,
    line: int,
    column: int,
    message: str,
    claim: str,
    suggestion: str,
) -> Finding:
    normalized = re.sub(r"\s+", " ", claim.strip().lower())
    try:
        stable_path = path.resolve().relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        stable_path = path.name
    material = f"{rule_id}\0{stable_path}\0{normalized}".encode()
    fingerprint = hashlib.sha256(material).hexdigest()[:16]
    return Finding(rule_id, severity, path, line, column, message, claim, suggestion, fingerprint)
