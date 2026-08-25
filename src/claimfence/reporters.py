from __future__ import annotations

from collections import Counter
import hashlib
import html
import json
from pathlib import Path

from . import __version__
from .models import ClaimRecord, EvidenceAnchor, Finding, ScanResult, Severity
from .rules import RULE_DESCRIPTIONS


MAX_HASH_BYTES = 16 * 1024 * 1024


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
            "claims_detected": len(result.claims),
            "claim_statuses": result.claim_counts(),
        },
        "findings": [finding.to_dict() for finding in result.findings],
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def ledger_report(result: ScanResult, root: Path) -> str:
    return json.dumps(ledger_payload(result, root), indent=2, sort_keys=True)


def ledger_payload(result: ScanResult, root: Path) -> dict[str, object]:
    claim_counts = result.claim_counts()
    return {
        "$schema": (
            "https://raw.githubusercontent.com/Dean00dev/ClaimFence/v0.6.0/"
            "schema/claim-ledger-v1.schema.json"
        ),
        "schema_version": "1.0",
        "tool": {"name": "ClaimFence", "version": __version__},
        "summary": {
            "files_scanned": result.files_scanned,
            "claims_detected": len(result.claims),
            "claim_statuses": claim_counts,
            "evidence_anchors": _evidence_count(result),
            "findings": len(result.findings),
            "finding_counts": result.counts(),
            "suppressed": result.suppressed,
            "baselined": result.baselined,
        },
        "claims": [_claim_payload(claim, root) for claim in result.claims],
        "interpretation": {
            "linked": "Required lexical context and at least one concrete anchor were detected.",
            "review": "At least one matched rule is missing required context.",
            "suppressed": "A missing-context match was suppressed with an inline reason.",
        },
        "limitations": [
            "Claim detection is lexical and incomplete.",
            "Linked does not mean true, sufficient, current, or independently verified.",
            "Commands are recorded but not executed.",
            "External URLs are recorded but not fetched or authenticated.",
            "Local SHA-256 digests establish byte identity only, not evidence quality.",
        ],
    }


def html_report(result: ScanResult, root: Path) -> str:
    counts = result.claim_counts()
    evidence_count = _evidence_count(result)
    cards = (
        ("Claims", len(result.claims), "all"),
        ("Linked", counts["linked"], "linked"),
        ("Needs review", counts["review"], "review"),
        ("Suppressed", counts["suppressed"], "suppressed"),
        ("Evidence anchors", evidence_count, "all"),
        ("Findings", len(result.findings), "review"),
    )
    card_markup = "".join(
        f'<div class="metric metric-{status}"><span>{html.escape(label)}</span>'
        f"<strong>{value}</strong></div>"
        for label, value, status in cards
    )
    claim_markup = "".join(_claim_html(claim, root) for claim in result.claims)
    if not claim_markup:
        claim_markup = (
            '<section class="empty"><h2>No matched assurance claims</h2>'
            "<p>The selected Markdown contained no phrases covered by this rule set.</p></section>"
        )
    version = html.escape(__version__)
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>ClaimFence Evidence Map</title>
  <style>
    :root {{ color-scheme: dark; --bg:#07111b; --panel:#0d1b2a; --line:#24364a;
      --text:#eef7ff; --muted:#9eb2c7; --cyan:#20d9ff; --green:#55e39b;
      --amber:#ffca6a; --violet:#a98bff; --red:#ff7b8c; }}
    * {{ box-sizing:border-box; }}
    body {{ margin:0; background:radial-gradient(circle at 80% -10%,#143a55 0,transparent 34%),
      var(--bg); color:var(--text); font:15px/1.55 ui-sans-serif,system-ui,-apple-system,
      BlinkMacSystemFont,"Segoe UI",sans-serif; }}
    main {{ width:min(1180px,calc(100% - 32px)); margin:0 auto; padding:44px 0 72px; }}
    header {{ display:grid; grid-template-columns:auto 1fr; gap:18px; align-items:center; }}
    .mark {{ width:64px;height:64px;border:1px solid #2e6076;border-radius:18px;display:grid;
      place-items:center;background:linear-gradient(145deg,#102b3a,#0b1724);font-size:31px;
      box-shadow:0 0 38px #20d9ff22; }}
    h1 {{ margin:0;font-size:clamp(28px,5vw,46px);letter-spacing:-.035em; }}
    .kicker {{ margin:3px 0 0;color:var(--cyan);font-weight:700;letter-spacing:.08em;
      text-transform:uppercase;font-size:12px; }}
    .boundary {{ margin:28px 0;padding:16px 18px;border:1px solid #725a27;
      background:#2a2112;border-radius:13px;color:#ffe2a1; }}
    .metrics {{ display:grid;grid-template-columns:repeat(6,minmax(0,1fr));gap:10px;margin:24px 0; }}
    .metric {{ background:#0d1b2add;border:1px solid var(--line);border-radius:14px;padding:14px; }}
    .metric span {{ display:block;color:var(--muted);font-size:12px; }}
    .metric strong {{ display:block;font-size:26px;margin-top:3px; }}
    .metric-linked strong {{ color:var(--green); }} .metric-review strong {{ color:var(--amber); }}
    .metric-suppressed strong {{ color:var(--violet); }}
    .toolbar {{ display:flex;gap:8px;flex-wrap:wrap;margin:28px 0 16px; }}
    button {{ appearance:none;border:1px solid var(--line);background:#0c1926;color:var(--text);
      padding:8px 13px;border-radius:999px;cursor:pointer;font-weight:700; }}
    button:hover,button[aria-pressed="true"] {{ border-color:var(--cyan);color:var(--cyan);
      background:#0c2735; }}
    .claim {{ background:linear-gradient(145deg,#0e1e2d,#0b1825);border:1px solid var(--line);
      border-left:4px solid var(--amber);border-radius:15px;padding:20px;margin:12px 0;
      box-shadow:0 12px 30px #0003; }}
    .claim-linked {{ border-left-color:var(--green); }} .claim-suppressed {{ border-left-color:var(--violet); }}
    .claim-head {{ display:flex;gap:12px;align-items:flex-start;justify-content:space-between; }}
    .claim h2 {{ font-size:17px;line-height:1.45;margin:8px 0 6px;overflow-wrap:anywhere; }}
    .source {{ color:var(--muted);font:12px ui-monospace,SFMono-Regular,Consolas,monospace; }}
    .status,.chip {{ display:inline-block;border:1px solid currentColor;border-radius:999px;
      padding:3px 8px;font-size:11px;font-weight:800;letter-spacing:.04em;text-transform:uppercase; }}
    .status-linked {{ color:var(--green); }} .status-review {{ color:var(--amber); }}
    .status-suppressed {{ color:var(--violet); }}
    .rules,.context {{ display:flex;gap:6px;flex-wrap:wrap;margin-top:10px; }}
    .chip {{ color:#bcd2e8;border-color:#3b5268;text-transform:none;letter-spacing:0; }}
    .chip-missing {{ color:var(--red);border-color:#77404a; }}
    .anchors {{ display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:8px;
      margin-top:15px; }}
    .anchor {{ border:1px solid #23384b;background:#08131e;border-radius:10px;padding:10px 12px;
      min-width:0; }}
    .anchor strong {{ color:var(--cyan);font-size:11px;text-transform:uppercase; }}
    .anchor code {{ display:block;color:#d8e6f4;margin-top:4px;overflow-wrap:anywhere;white-space:normal; }}
    .anchor small {{ display:block;color:var(--muted);margin-top:5px; }}
    .empty {{ text-align:center;border:1px dashed var(--line);border-radius:16px;padding:46px; }}
    footer {{ color:var(--muted);margin-top:30px;font-size:13px; }}
    [hidden] {{ display:none !important; }}
    @media (max-width:850px) {{ .metrics {{ grid-template-columns:repeat(3,1fr); }} }}
    @media (max-width:520px) {{ main {{ width:min(100% - 20px,1180px);padding-top:24px; }}
      .metrics {{ grid-template-columns:repeat(2,1fr); }} .claim-head {{ display:block; }}
      .status {{ margin-bottom:5px; }} }}
  </style>
</head>
<body>
<main>
  <header><div class="mark" aria-hidden="true">◈</div><div><div class="kicker">ClaimFence v{version}</div>
    <h1>Evidence Map</h1><p>Assurance language, its declared boundary, and its concrete anchors.</p></div></header>
  <aside class="boundary"><strong>Interpretation boundary:</strong> “Linked” means required lexical
    context and an anchor were detected. It does not mean the claim is true or the evidence is sufficient.
    Commands were not executed; external URLs were not fetched; local hashes establish byte identity only.</aside>
  <section class="metrics" aria-label="Scan summary">{card_markup}</section>
  <nav class="toolbar" aria-label="Filter claims">
    <button type="button" data-filter="all" aria-pressed="true">All claims</button>
    <button type="button" data-filter="linked" aria-pressed="false">Linked</button>
    <button type="button" data-filter="review" aria-pressed="false">Needs review</button>
    <button type="button" data-filter="suppressed" aria-pressed="false">Suppressed</button>
  </nav>
  <div id="claims">{claim_markup}</div>
  <footer>Generated deterministically from repository Markdown. No network requests or model calls were made.</footer>
</main>
<script>
  for (const button of document.querySelectorAll('[data-filter]')) {{
    button.addEventListener('click', () => {{
      const filter = button.dataset.filter;
      for (const item of document.querySelectorAll('.claim'))
        item.hidden = filter !== 'all' && item.dataset.status !== filter;
      for (const other of document.querySelectorAll('[data-filter]'))
        other.setAttribute('aria-pressed', String(other === button));
    }});
  }}
</script>
</body>
</html>"""


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
    claim_counts = result.claim_counts()
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
        "claims-count": len(result.claims),
        "linked-claims-count": claim_counts["linked"],
        "review-claims-count": claim_counts["review"],
        "suppressed-claims-count": claim_counts["suppressed"],
        "evidence-anchors-count": _evidence_count(result),
        "outcome": outcome,
    }
    return "\n".join(f"{name}={value}" for name, value in values.items())


def _claim_payload(claim: ClaimRecord, root: Path) -> dict[str, object]:
    payload: dict[str, object] = {
        "id": claim.claim_id,
        "rules": list(claim.rule_ids),
        "severity": claim.severity.label(),
        "path": _relative(claim.path, root),
        "line": claim.line,
        "column": claim.column,
        "text": claim.text,
        "status": claim.status,
        "context": {
            "required": list(claim.required_context),
            "present": list(claim.present_context),
            "missing": list(claim.missing_context),
        },
        "suppression_reasons": list(claim.suppression_reasons),
        "evidence": [_anchor_payload(anchor, root) for anchor in claim.evidence],
    }
    if claim.explicit_id is not None:
        payload["stable_id"] = claim.explicit_id
    return payload


def _evidence_count(result: ScanResult) -> int:
    anchors = {
        (anchor.kind, anchor.target, anchor.line, anchor.column)
        for claim in result.claims
        for anchor in claim.evidence
    }
    return len(anchors)


def _claim_html(claim: ClaimRecord, root: Path) -> str:
    status_label = {
        "linked": "Linked",
        "review": "Needs review",
        "suppressed": "Suppressed",
    }[claim.status]
    rules = "".join(f'<span class="chip">{html.escape(rule)}</span>' for rule in claim.rule_ids)
    present = "".join(
        f'<span class="chip">has {html.escape(value)}</span>'
        for value in claim.present_context
    )
    missing = "".join(
        f'<span class="chip chip-missing">missing {html.escape(value)}</span>'
        for value in claim.missing_context
    )
    reasons = "".join(
        f'<span class="chip">reason: {html.escape(reason)}</span>'
        for reason in claim.suppression_reasons
    )
    anchors = "".join(_anchor_html(anchor, root) for anchor in claim.evidence)
    if not anchors:
        anchors = (
            '<div class="anchor"><strong>No concrete anchor</strong>'
            "<small>No command, URL, or repository-local evidence reference was detected nearby.</small></div>"
        )
    source = f"{_relative(claim.path, root)}:{claim.line}:{claim.column} · {claim.claim_id}"
    if claim.explicit_id is not None:
        source += f" · stable-id {claim.explicit_id}"
    return (
        f'<article class="claim claim-{claim.status}" data-status="{claim.status}">'
        '<div class="claim-head"><div>'
        f'<div class="rules">{rules}</div><h2>{html.escape(claim.text)}</h2>'
        f'<div class="source">{html.escape(source)}</div></div>'
        f'<span class="status status-{claim.status}">{status_label}</span></div>'
        f'<div class="context">{present}{missing}{reasons}</div>'
        f'<div class="anchors">{anchors}</div></article>'
    )


def _anchor_html(anchor: EvidenceAnchor, root: Path) -> str:
    payload = _anchor_payload(anchor, root)
    details: list[str] = [str(payload["status"])]
    if repository_path := payload.get("repository_path"):
        details.append(str(repository_path))
    if (size_bytes := payload.get("size_bytes")) is not None:
        details.append(f"{size_bytes} bytes")
    if digest := payload.get("sha256"):
        details.append(f"sha256 {str(digest)[:16]}…")
    return (
        '<div class="anchor">'
        f"<strong>{html.escape(anchor.kind)}</strong>"
        f"<code>{html.escape(anchor.target)}</code>"
        f"<small>{html.escape(' · '.join(details))}</small></div>"
    )


def _anchor_payload(anchor: EvidenceAnchor, root: Path) -> dict[str, object]:
    payload = anchor.to_dict()
    if (
        anchor.kind != "local-file"
        or anchor.status != "present"
        or not anchor.repository_path
        or anchor.size_bytes is None
        or anchor.size_bytes > MAX_HASH_BYTES
    ):
        return payload
    candidate = (root / anchor.repository_path).resolve()
    try:
        candidate.relative_to(root.resolve())
    except ValueError:
        payload["status"] = "outside-root"
        return payload
    digest = hashlib.sha256()
    with candidate.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    payload["sha256"] = digest.hexdigest()
    return payload


def _relative(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def _escape(value: str) -> str:
    escaped = value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    return escaped.replace(":", "%3A").replace(",", "%2C")
