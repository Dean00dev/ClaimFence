from __future__ import annotations

from dataclasses import dataclass
import fnmatch
import hashlib
from pathlib import Path
import re
from typing import Iterable
from urllib.parse import unquote, urlsplit

from .config import Config
from .models import Finding, ScanResult, Severity
from .rules import (
    COMMAND_PATTERN,
    LIMITATION_PATTERN,
    RULES,
    SCOPE_PATTERN,
    SUPPRESSION_PATTERN,
)


MARKDOWN_SUFFIXES = {".md", ".mdx", ".markdown"}
MARKDOWN_LINK_PATTERN = re.compile(
    r"!?\[[^\]]*\]\(\s*(?P<target><[^>]+>|[^)\s]+)",
    re.MULTILINE,
)
INLINE_CODE_PATTERN = re.compile(r"(?P<ticks>`+)(?P<code>.*?)(?P=ticks)", re.DOTALL)
BARE_URL_PATTERN = re.compile(r"https?://[^\s>)]+", re.IGNORECASE)
PATH_TOKEN_PATTERN = re.compile(
    r"(?<![\w.-])(?P<path>"
    r"(?:\.{1,2}/)?[A-Za-z0-9_.@+-]+(?:/[A-Za-z0-9_.@+-]+)+"
    r"|[A-Za-z0-9_.@+-]+\.(?:md|markdown|mdx|json|ya?ml|toml|txt|log|xml|html?|"
    r"py|js|mjs|cjs|ts|tsx|jsx|rs|go|java|sh|ps1)"
    r")(?![\w.-])",
    re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class SourcePosition:
    line: int
    column: int


@dataclass(frozen=True, slots=True)
class ProseBlock:
    raw_text: str
    scan_text: str
    positions: tuple[SourcePosition, ...]
    kind: str

    @property
    def start_line(self) -> int:
        return self.positions[0].line


@dataclass(frozen=True, slots=True)
class EvidenceReference:
    target: str
    position: SourcePosition
    relative_to_document: bool


def scan_paths(
    paths: Iterable[Path],
    config: Config,
    root: Path | None = None,
) -> ScanResult:
    repository_root = (root or Path.cwd()).resolve()
    if not repository_root.is_dir():
        raise FileNotFoundError(f"repository root not found: {repository_root}")

    result = ScanResult()
    requested = list(paths)
    missing = [path for path in requested if not path.exists()]
    if missing:
        raise FileNotFoundError(f"path not found: {missing[0]}")
    for path in _discover(requested, config.exclude):
        result.files_scanned += 1
        file_findings, suppressed = scan_file(path, config, repository_root)
        result.findings.extend(file_findings)
        result.suppressed += suppressed
    result.findings.sort(
        key=lambda finding: (
            finding.path.as_posix(),
            finding.line,
            finding.column,
            finding.rule_id,
        )
    )
    return result


def scan_file(
    path: Path,
    config: Config,
    root: Path | None = None,
) -> tuple[list[Finding], int]:
    repository_root = (root or Path.cwd()).resolve()
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()
    blocks = _logical_blocks(lines)
    suppression_map = _block_suppressions(lines, blocks)
    headings = [block.scan_text.strip().lower() for block in blocks if block.kind == "heading"]
    findings: list[Finding] = []
    suppressed = 0
    assurance_blocks: list[int] = []
    claim_blocks: set[int] = set()

    for index, block in enumerate(blocks):
        line = block.scan_text
        for rule in RULES:
            if rule.rule_id in config.disabled_rules:
                continue
            for match in rule.pattern.finditer(line):
                if _is_negated(line, match.start()) or _is_non_assurance_usage(
                    rule.rule_id, line, match
                ):
                    continue
                claim_blocks.add(index)
                context = _context(blocks, index, config.context_radius())
                present = _context_types(
                    context,
                    config.extra_evidence_terms,
                    path,
                    repository_root,
                )
                if rule.required_context.issubset(present):
                    continue
                block_suppressions = suppression_map.get(index, set())
                if rule.rule_id in block_suppressions or "ALL" in block_suppressions:
                    suppressed += 1
                    continue
                position = block.positions[match.start()]
                claim = _claim_excerpt(line, match.start())
                findings.append(
                    _finding(
                        rule.rule_id,
                        rule.severity,
                        path,
                        position.line,
                        position.column,
                        rule.message,
                        claim,
                        rule.suggestion,
                        repository_root,
                    )
                )
                if rule.rule_id in {"CF001", "CF002", "CF003"}:
                    assurance_blocks.append(index)
                break

    if "CF005" not in config.disabled_rules:
        reference_findings, reference_suppressed = _reference_findings(
            blocks,
            claim_blocks,
            suppression_map,
            path,
            repository_root,
            config.context_radius(),
        )
        findings.extend(reference_findings)
        suppressed += reference_suppressed

    if assurance_blocks:
        first_index = assurance_blocks[0]
        first_block = blocks[first_index]
        first_position = first_block.positions[0]
        first_claim = _claim_excerpt(first_block.scan_text, 0)
        if "CF101" not in config.disabled_rules and not any(
            re.search(
                r"\b(?:limitations?|boundaries|non-goals?|what\s+it\s+does\s+not)\b",
                heading,
                re.I,
            )
            for heading in headings
        ):
            findings.append(
                _finding(
                    "CF101",
                    Severity.WARNING,
                    path,
                    first_position.line,
                    first_position.column,
                    "assurance claims appear in a document with no limitations section",
                    first_claim,
                    "Add a clearly titled limitations, boundaries, non-goals, or "
                    "'what this does not establish' section.",
                    repository_root,
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
                    first_position.line,
                    first_position.column,
                    "assurance claims appear in a document with no verification section",
                    first_claim,
                    "Add a verification or reproduction section with exact commands and "
                    "expected evidence.",
                    repository_root,
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


def _logical_blocks(lines: list[str]) -> list[ProseBlock]:
    blocks: list[ProseBlock] = []
    raw: list[str] = []
    positions: list[SourcePosition] = []
    kind: str | None = None
    fence_marker: str | None = None
    fence_length = 0
    in_comment = False

    def flush() -> None:
        nonlocal raw, positions, kind
        if raw and kind:
            raw_text = "".join(raw)
            blocks.append(
                ProseBlock(raw_text, _mask_inline_markup(raw_text), tuple(positions), kind)
            )
        raw = []
        positions = []
        kind = None

    def append_segment(line: str, line_number: int, start: int, end: int) -> None:
        stripped_start = start
        stripped_end = end
        while stripped_start < stripped_end and line[stripped_start].isspace():
            stripped_start += 1
        while stripped_end > stripped_start and line[stripped_end - 1].isspace():
            stripped_end -= 1
        if stripped_start == stripped_end:
            return
        if raw:
            raw.append(" ")
            positions.append(SourcePosition(line_number, stripped_start + 1))
        raw.extend(line[stripped_start:stripped_end])
        positions.extend(
            SourcePosition(line_number, column + 1)
            for column in range(stripped_start, stripped_end)
        )

    for line_number, original in enumerate(lines, start=1):
        fence = re.match(r"^\s{0,3}(`{3,}|~{3,})", original)
        if fence:
            marker = fence.group(1)[0]
            length = len(fence.group(1))
            if fence_marker is None:
                flush()
                fence_marker = marker
                fence_length = length
            elif marker == fence_marker and length >= fence_length:
                fence_marker = None
                fence_length = 0
            continue
        if fence_marker is not None:
            continue

        line, in_comment = _mask_html_comments(original, in_comment)
        if not line.strip():
            flush()
            continue

        heading = re.match(r"^\s{0,3}#{1,6}\s+(?P<body>.+?)\s*#*\s*$", line)
        if heading:
            flush()
            kind = "heading"
            append_segment(line, line_number, heading.start("body"), heading.end("body"))
            flush()
            continue

        if re.match(r"^\s{0,3}(?:=+|-+)\s*$", line) and kind == "paragraph":
            kind = "heading"
            flush()
            continue

        if re.match(r"^\s{0,3}(?:(?:\*\s*){3,}|(?:_\s*){3,})$", line):
            flush()
            continue

        quote = re.match(r"^\s{0,3}>\s?(?P<body>.*)$", line)
        list_item = re.match(r"^\s{0,3}(?:[-+*]|\d+[.)])\s+(?P<body>.*)$", line)

        if quote:
            if kind not in {None, "quote"}:
                flush()
            kind = "quote"
            append_segment(line, line_number, quote.start("body"), quote.end("body"))
            continue

        if list_item:
            flush()
            kind = "list"
            append_segment(
                line,
                line_number,
                list_item.start("body"),
                list_item.end("body"),
            )
            continue

        if re.match(r"^(?: {4}|\t)", line) and kind != "list":
            flush()
            continue

        if kind is None:
            kind = "paragraph"
        elif kind not in {"paragraph", "list"}:
            flush()
            kind = "paragraph"
        append_segment(line, line_number, 0, len(line))

    flush()
    return blocks


def _mask_html_comments(line: str, in_comment: bool) -> tuple[str, bool]:
    masked = list(line)
    cursor = 0
    while cursor < len(line):
        if in_comment:
            end = line.find("-->", cursor)
            if end == -1:
                for index in range(cursor, len(masked)):
                    masked[index] = " "
                return "".join(masked), True
            for index in range(cursor, end + 3):
                masked[index] = " "
            cursor = end + 3
            in_comment = False
            continue
        start = line.find("<!--", cursor)
        if start == -1:
            break
        end = line.find("-->", start + 4)
        if end == -1:
            for index in range(start, len(masked)):
                masked[index] = " "
            return "".join(masked), True
        for index in range(start, end + 3):
            masked[index] = " "
        cursor = end + 3
    return "".join(masked), in_comment


def _mask_inline_markup(raw_text: str) -> str:
    masked = list(raw_text)
    for match in INLINE_CODE_PATTERN.finditer(raw_text):
        for index in range(match.start(), match.end()):
            masked[index] = " "
    for match in MARKDOWN_LINK_PATTERN.finditer(raw_text):
        target_start = match.start("target")
        for index in range(max(match.start(), target_start - 1), match.end("target") + 1):
            if index < len(masked):
                masked[index] = " "
    for match in re.finditer(r"<\s*(?:https?://|mailto:)[^>]+>", raw_text, re.I):
        for index in range(match.start(), match.end()):
            masked[index] = " "
    return "".join(masked)


def _block_suppressions(lines: list[str], blocks: list[ProseBlock]) -> dict[int, set[str]]:
    directives: dict[int, set[str]] = {}
    for line_number, line in enumerate(lines, start=1):
        match = SUPPRESSION_PATTERN.search(line)
        if match:
            directives[line_number + 1] = {
                value.strip().upper() for value in match.group(1).split(",")
            }
    return {
        index: directives[block.start_line]
        for index, block in enumerate(blocks)
        if block.start_line in directives
    }


def _context(blocks: list[ProseBlock], index: int, radius: int) -> list[ProseBlock]:
    start = max(0, index - radius)
    end = min(len(blocks), index + radius + 1)
    return blocks[start:end]


def _context_types(
    blocks: list[ProseBlock],
    extra_evidence_terms: list[str],
    document: Path,
    root: Path,
) -> set[str]:
    raw_context = "\n".join(block.raw_text for block in blocks)
    scan_context = "\n".join(block.scan_text for block in blocks)
    result: set[str] = set()
    if any(term.lower() in raw_context.lower() for term in extra_evidence_terms) or any(
        _block_has_concrete_evidence(block, document, root) for block in blocks
    ):
        result.add("evidence")
    if SCOPE_PATTERN.search(scan_context):
        result.add("scope")
    if LIMITATION_PATTERN.search(scan_context):
        result.add("limitation")
    return result


def _block_has_concrete_evidence(block: ProseBlock, document: Path, root: Path) -> bool:
    if BARE_URL_PATTERN.search(block.raw_text):
        return True
    for match in INLINE_CODE_PATTERN.finditer(block.raw_text):
        code = match.group("code").strip()
        if COMMAND_PATTERN.search(code):
            return True
    for reference in _evidence_references(block):
        if _reference_supports_evidence(reference, document, root):
            return True
    return False


def _evidence_references(block: ProseBlock) -> list[EvidenceReference]:
    references: list[EvidenceReference] = []
    for match in MARKDOWN_LINK_PATTERN.finditer(block.raw_text):
        target = match.group("target").strip("<>")
        position = block.positions[match.start("target")]
        references.append(EvidenceReference(target, position, True))

    for code_match in INLINE_CODE_PATTERN.finditer(block.raw_text):
        code = code_match.group("code")
        if not (COMMAND_PATTERN.search(code) or PATH_TOKEN_PATTERN.fullmatch(code.strip())):
            continue
        for path_match in PATH_TOKEN_PATTERN.finditer(code):
            raw_index = code_match.start("code") + path_match.start("path")
            position = block.positions[raw_index]
            references.append(EvidenceReference(path_match.group("path"), position, False))
    return references


def _reference_findings(
    blocks: list[ProseBlock],
    claim_blocks: set[int],
    suppression_map: dict[int, set[str]],
    document: Path,
    root: Path,
    radius: int,
) -> tuple[list[Finding], int]:
    findings: list[Finding] = []
    suppressed = 0
    seen: set[tuple[int, int, str]] = set()
    block_indexes = {id(block): index for index, block in enumerate(blocks)}
    for claim_index in sorted(claim_blocks):
        for block in _context(blocks, claim_index, radius):
            block_index = block_indexes[id(block)]
            for reference in _evidence_references(block):
                key = (reference.position.line, reference.position.column, reference.target)
                if key in seen:
                    continue
                seen.add(key)
                issue = _reference_issue(reference, document, root)
                if issue is None:
                    continue
                block_suppressions = suppression_map.get(block_index, set())
                if "CF005" in block_suppressions or "ALL" in block_suppressions:
                    suppressed += 1
                    continue
                findings.append(
                    _finding(
                        "CF005",
                        Severity.WARNING,
                        document,
                        reference.position.line,
                        reference.position.column,
                        issue,
                        reference.target,
                        "Point to an existing path inside the repository, or remove the "
                        "reference as evidence.",
                        root,
                    )
                )
    return findings, suppressed


def _reference_issue(reference: EvidenceReference, document: Path, root: Path) -> str | None:
    target = reference.target.strip().strip("<>")
    if not target or target.startswith(("#", "/", "//")):
        return None
    parsed = urlsplit(target)
    if parsed.scheme or parsed.netloc:
        return None
    path_text = unquote(parsed.path)
    if not path_text:
        return None
    base = document.parent if reference.relative_to_document else root
    candidate = (base / path_text).resolve()
    try:
        candidate.relative_to(root.resolve())
    except ValueError:
        return "local evidence reference escapes the repository root"
    if not candidate.exists():
        return "local evidence reference does not exist"
    return None


def _reference_supports_evidence(
    reference: EvidenceReference,
    document: Path,
    root: Path,
) -> bool:
    target = reference.target.strip().strip("<>")
    if not target or target.startswith(("#", "/", "//")):
        return False
    parsed = urlsplit(target)
    if parsed.scheme or parsed.netloc:
        return parsed.scheme.lower() in {"http", "https"}
    return bool(parsed.path) and _reference_issue(reference, document, root) is None


def _is_negated(text: str, start: int) -> bool:
    prefix = text[max(0, start - 180):start]
    immediate = re.search(
        r"\b(?:not|isn['’]?t|aren['’]?t|doesn['’]?t|does\s+not|cannot|can['’]?t)\s+$",
        prefix,
        re.I,
    )
    epistemic = re.search(
        r"\b(?:cannot|can['’]?t|does\s+not|doesn['’]?t|do\s+not|don['’]?t)\s+"
        r"(?:determine|establish|verify|confirm|claim|show|prove|mean|demonstrate)\b"
        r"[^.!?;]{0,130}$",
        prefix,
        re.I,
    )
    no_evidence = re.search(r"\bno\s+evidence\b[^.!?;]{0,130}$", prefix, re.I)
    return bool(immediate or epistemic or no_evidence)


def _is_non_assurance_usage(rule_id: str, text: str, match: re.Match[str]) -> bool:
    if rule_id != "CF002":
        return False
    start = match.start()
    prefix = text[max(0, start - 100):start]
    if re.search(
        r"\b(?:needed|required|necessary|intended|used)\s+to\s+$",
        prefix,
        re.IGNORECASE,
    ):
        return True
    if match.group(0).lower() in {"block", "blocks"}:
        suffix = text[match.end():match.end() + 80]
        return not bool(
            re.match(
                r"\s+(?:attacks?|requests?|traffic|access|execution|calls?|inputs?|tokens?|"
                r"malware|exploits?|bypasses?|connections?|operations?|changes?)\b",
                suffix,
                re.IGNORECASE,
            )
        )
    return False


def _claim_excerpt(text: str, start: int) -> str:
    sentence_start = max(text.rfind(mark, 0, start) for mark in ".!?;") + 1
    ends = [position for mark in ".!?;" if (position := text.find(mark, start)) != -1]
    sentence_end = min(ends) + 1 if ends else len(text)
    return re.sub(r"\s+", " ", text[sentence_start:sentence_end].strip())


def _finding(
    rule_id: str,
    severity: Severity,
    path: Path,
    line: int,
    column: int,
    message: str,
    claim: str,
    suggestion: str,
    root: Path,
) -> Finding:
    normalized = re.sub(r"\s+", " ", claim.strip().lower())
    try:
        stable_path = path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        stable_path = path.name
    material = f"{rule_id}\0{stable_path}\0{normalized}".encode()
    fingerprint = hashlib.sha256(material).hexdigest()[:16]
    return Finding(rule_id, severity, path, line, column, message, claim, suggestion, fingerprint)
