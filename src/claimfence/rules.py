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
            r"\b(?:all|every|never|always|zero)\s+(?:attacks?|bypasses?|failures?|false\s+positives?|"
            r"vulnerabilit(?:y|ies)|violations?|errors?)\b",
            re.IGNORECASE,
        ),
        "universal or zero-result claim lacks nearby test conditions",
        "Name the campaign size, input space, version, and evidence that produced this result.",
        frozenset({"scope", "evidence"}),
    ),
    PhraseRule(
        "CF004",
        Severity.INFO,
        re.compile(
            r"\b(?:passes?|passed|green)\s+(?:all\s+)?(?:\d[\d,]*|the)\s+(?:tests?|checks?|cases?|scenarios?)\b",
            re.IGNORECASE,
        ),
        "test-result claim has no nearby reproduction path",
        "Link the CI run, receipt, or exact command needed to reproduce the result.",
        frozenset({"evidence"}),
    ),
)


EVIDENCE_PATTERNS = (
    re.compile(r"\b(?:test(?:ed|s|ing)?|benchmark|evidence|report|receipt|reproduc(?:e|ible|tion)|"
               r"verify|verification|CI|workflow|artifact|fixture|counterexample|mutation)\b", re.I),
    re.compile(r"\[[^\]]+\]\([^)]+\)"),
    re.compile(r"`(?:pytest|python\s+-m|npm\s+(?:test|run)|cargo\s+test|go\s+test|make\s+test)[^`]*`", re.I),
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
    "CF003": "Universal or zero-result claim",
    "CF004": "Unanchored test-result claim",
    "CF101": "Assurance claims without a limitations section",
    "CF102": "Assurance claims without a verification section",
}
