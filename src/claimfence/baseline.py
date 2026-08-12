from __future__ import annotations

import json
from pathlib import Path

from .models import ScanResult


def apply_baseline(result: ScanResult, path: Path | None) -> None:
    if path is None:
        return
    if not path.exists():
        raise FileNotFoundError(f"baseline file not found: {path}")
    raw = json.loads(path.read_text(encoding="utf-8"))
    fingerprints = set(raw.get("fingerprints", []))
    retained = []
    for finding in result.findings:
        if finding.fingerprint in fingerprints:
            result.baselined += 1
        else:
            retained.append(finding)
    result.findings = retained


def write_baseline(result: ScanResult, path: Path) -> None:
    payload = {
        "version": 1,
        "fingerprints": sorted({finding.fingerprint for finding in result.findings}),
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
