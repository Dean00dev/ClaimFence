from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path


def stable_claim_id(explicit_id: str) -> str:
    material = f"explicit\0{explicit_id}".encode()
    return f"CLM-{hashlib.sha256(material).hexdigest()[:16]}"


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


@dataclass(frozen=True, slots=True)
class EvidenceAnchor:
    kind: str
    target: str
    status: str
    line: int
    column: int
    repository_path: str | None = None
    sha256: str | None = None
    size_bytes: int | None = None

    def to_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "kind": self.kind,
            "target": self.target,
            "status": self.status,
            "line": self.line,
            "column": self.column,
        }
        if self.repository_path is not None:
            payload["repository_path"] = self.repository_path
        if self.sha256 is not None:
            payload["sha256"] = self.sha256
        if self.size_bytes is not None:
            payload["size_bytes"] = self.size_bytes
        return payload


@dataclass(frozen=True, slots=True)
class ClaimRecord:
    claim_id: str
    explicit_id: str | None
    rule_ids: tuple[str, ...]
    severity: Severity
    path: Path
    line: int
    column: int
    text: str
    status: str
    required_context: tuple[str, ...]
    present_context: tuple[str, ...]
    missing_context: tuple[str, ...]
    evidence: tuple[EvidenceAnchor, ...]
    suppression_reasons: tuple[str, ...] = ()


@dataclass(slots=True)
class ScanResult:
    files_scanned: int = 0
    findings: list[Finding] = field(default_factory=list)
    claims: list[ClaimRecord] = field(default_factory=list)
    suppressed: int = 0
    baselined: int = 0

    def counts(self) -> dict[str, int]:
        return {
            severity.label(): sum(f.severity == severity for f in self.findings)
            for severity in Severity
        }

    def fails_at(self, threshold: Severity | None) -> bool:
        return threshold is not None and any(
            finding.severity >= threshold for finding in self.findings
        )

    def claim_counts(self) -> dict[str, int]:
        return {
            status: sum(claim.status == status for claim in self.claims)
            for status in ("linked", "review", "suppressed")
        }
