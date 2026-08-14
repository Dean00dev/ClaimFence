from __future__ import annotations

from dataclasses import dataclass
import re

from .models import Severity


@dataclass(frozen=True, slots=True)
class PhraseRule:
    rule_id: str
    severity: Severity
    pattern: re.Pattern[str]
    message: str
    suggestion: str
    required_context: frozenset[str] = frozenset()


RULES = (
    PhraseRule(
        "CF001",
        Severity.ERROR,
        re.compile(
            r"\b(?:unbreakable|unhackable|impossible\s+to\s+(?:bypass|exploit|compromise)|"
            r"(?:100|one\s+hundred)\s*%\s+(?:secure|safe|accurate)|"
            r"guarantees?\s+(?:security|safety|accuracy|prevention))\b",
            re.IGNORECASE,
        ),
        "absolute assurance claim",
        "Replace the absolute with a bounded, falsifiable claim and name the tested conditions.",
        frozenset({"scope", "evidence"}),
    ),
    PhraseRule(
        "CF002",
        Severity.WARNING,
        re.compile(
            r"\b(?:secure|safe|verified|validated|hardened|production[- ]ready|battle[- ]tested|"
            r"prevents?|protects?|blocks?|stops?|eliminates?|ensures?)\b",
            re.IGNORECASE,
        ),
        "assurance language lacks nearby evidence or scope",
        "Add a test/report link and state the version, configuration, or conditions covered.",
        frozenset({"scope", "evidence"}),
    ),
    PhraseRule(
        "CF003",
        Severity.WARNING,
        re.compile(
            r"\b(?:"
            r"(?:all|every|zero)\s+(?:attacks?|bypasses?|failures?|false\s+positives?|"
            r"vulnerabilit(?:y|ies)|violations?|errors?)"
            r"|(?:never|always)\s+(?:receives?|sends?|stores?|logs?|exposes?|transmits?|"
            r"shares?|leaks?|persists?|writes?|returns?|accepts?|allows?|executes?|contacts?|"
            r"calls?|fails?|errors?)"
            r"|(?:does|do|can|will)\s+not\s+(?:receive|send|store|log|expose|transmit|"
            r"share|leak|persist|write|return|accept|allow|execute|contact|call)"
            r"|(?:makes?|performs?)\s+no\s+(?:external\s+)?(?:calls?|requests?)"
            r"|no\s+(?:data|requests?|keys?|secrets?|tokens?|credentials?)\s+"
            r"(?:leaves?|reaches?|crosses?|is\s+sent|is\s+stored)"
            r")\b",
            re.IGNORECASE,
        ),
        "universal, zero-result, or universal-negative claim lacks nearby test conditions",
        "Name the relevant boundary, version, and evidence that supports this universal claim.",
        frozenset({"scope", "evidence"}),
    ),
    PhraseRule(
        "CF004",
        Severity.INFO,
        re.compile(
            r"\b(?:passes?|passed|green)\s+(?:all\s+)?(?:\d[\d,]*|the)\s+"
            r"(?:tests?|checks?|cases?|scenarios?)\b",
            re.IGNORECASE,
        ),
        "test-result claim has no nearby reproduction path",
        "Link the CI run, receipt, or exact command needed to reproduce the result.",
        frozenset({"evidence"}),
    ),
)


COMMAND_PATTERN = re.compile(
    r"^\s*\$?\s*(?:pytest|python(?:3)?\s+-m\s+(?:pytest|unittest)|"
    r"npm\s+(?:test|run\b)|"
    r"cargo\s+test|go\s+test|make\s+\S*test\b|tox\b|nox\b)",
    re.IGNORECASE,
)

SCOPE_PATTERN = re.compile(
    r"\b(?:under|within|for\s+(?:version|v?\d|this)|when|configuration|fixture|scenario|"
    r"campaign|bounded|tested\s+on|as\s+of|prototype|reference\s+implementation|"
    r"in\s+(?:version|v?\d|the\s+included|this\s+release))\b",
    re.IGNORECASE,
)

LIMITATION_PATTERN = re.compile(
    r"\b(?:not|no\s+guarantee|does\s+not|cannot|can['’]?t|limitation|out\s+of\s+scope|"
    r"prototype|experimental|not\s+production|doesn['’]?t)\b",
    re.IGNORECASE,
)

SECTION_PATTERN = re.compile(r"^\s{0,3}#{1,6}\s+(.+?)\s*$")
SUPPRESSION_PATTERN = re.compile(
    r"<!--\s*claimfence-disable-next-line\s+([A-Z0-9, -]+?)\s*:\s*(\S.+?)\s*-->",
    re.IGNORECASE,
)


RULE_DESCRIPTIONS = {
    "CF001": "Absolute assurance claim",
    "CF002": "Unbounded assurance language",
    "CF003": "Universal, zero-result, or universal-negative claim",
    "CF004": "Unanchored test-result claim",
    "CF005": "Broken local evidence reference",
    "CF101": "Assurance claims without a limitations section",
    "CF102": "Assurance claims without a verification section",
}
