from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path


class Severity(IntEnum):
    INFO = 1
    WARNING = 2
    ERROR = 3

    @classmethod
    def parse(cls, value: str) -> "Severity":
        try:
            return cls[value.strip().upper()]
        except KeyError as exc:
            raise ValueError(f"unknown severity: {value}") from exc

    def label(self) -> str:
        return self.name.lower()


@dataclass(frozen=True, slots=True)
class Finding:
    rule_id: str
    severity: Severity
    path: Path
    line: int
    column: int
    message: str
    claim: str
    suggestion: str
    fingerprint: str

    def to_dict(self) -> dict[str, object]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.label(),
            "path": self.path.as_posix(),
            "line": self.line,
            "column": self.column,
            "message": self.message,
            "claim": self.claim,
            "suggestion": self.suggestion,
            "fingerprint": self.fingerprint,
        }


@dataclass(slots=True)
class ScanResult:
    files_scanned: int = 0
    findings: list[Finding] = field(default_factory=list)
    suppressed: int = 0
    baselined: int = 0

    def counts(self) -> dict[str, int]:
        return {
            severity.label(): sum(f.severity == severity for f in self.findings)
            for severity in Severity
        }
