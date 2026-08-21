from __future__ import annotations

from collections import Counter
import html
import json
from pathlib import Path
import re
from typing import Any

from . import __version__


DRIFT_SCHEMA = (
    "https://raw.githubusercontent.com/Dean00dev/ClaimFence/v0.5.1/"
    "schema/evidence-drift-v1.schema.json"
)
EVENT_KINDS = (
    "claim-added",
    "claim-removed",
    "claim-field-changed",
    "evidence-added",
    "evidence-removed",
    "evidence-changed",
)
_EVENT_ORDER = {kind: index for index, kind in enumerate(EVENT_KINDS)}
_CLAIM_ID = re.compile(r"^CLM-[0-9a-f]{16}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SEVERITY_RANK = {"info": 1, "warning": 2, "error": 3}
_ANCHOR_KINDS = {"command", "external-url", "local-file", "local-path"}
_ANCHOR_STATUSES = {
    "present",
    "present-unhashed",
    "directory",
    "missing",
    "outside-root",
    "not-executed",
    "not-fetched",
}
MAX_LEDGER_BYTES = 32 * 1024 * 1024


def load_ledger(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise FileNotFoundError(f"claim ledger not found: {path}")
    with path.open("rb") as stream:
        raw = stream.read(MAX_LEDGER_BYTES + 1)
    if len(raw) > MAX_LEDGER_BYTES:
        raise ValueError(
            f"claim ledger exceeds the {MAX_LEDGER_BYTES // (1024 * 1024)} MiB limit: {path}"
        )
    try:
        payload = json.loads(raw.decode("utf-8"))
    except RecursionError as exc:
        raise ValueError(f"claim ledger is nested too deeply: {path}") from exc
    validate_ledger(payload, source=str(path))
    return payload


def validate_ledger(payload: object, *, source: str = "claim ledger") -> None:
    if not isinstance(payload, dict):
        raise ValueError(f"{source} must contain a JSON object")
    if payload.get("schema_version") != "1.0":
        raise ValueError(f"{source} uses an unsupported schema_version")
    tool = payload.get("tool")
    if not isinstance(tool, dict) or tool.get("name") != "ClaimFence":
        raise ValueError(f"{source} was not produced by ClaimFence")
    if not isinstance(tool.get("version"), str) or not tool["version"]:
        raise ValueError(f"{source} has no valid tool version")
    claims = payload.get("claims")
    if not isinstance(claims, list):
        raise ValueError(f"{source} claims must be an array")
    summary = payload.get("summary")
    if not isinstance(summary, dict):
        raise ValueError(f"{source} summary must be an object")
    claims_detected = summary.get("claims_detected")
    if (
        isinstance(claims_detected, bool)
        or not isinstance(claims_detected, int)
        or claims_detected != len(claims)
    ):
        raise ValueError(f"{source} summary claims_detected does not match claims")

    seen: set[str] = set()
    for index, claim in enumerate(claims):
        label = f"{source} claim {index}"
        if not isinstance(claim, dict):
            raise ValueError(f"{label} must be an object")
        claim_id = claim.get("id")
        if not isinstance(claim_id, str) or not _CLAIM_ID.fullmatch(claim_id):
            raise ValueError(f"{label} has an invalid id")
        if claim_id in seen:
            raise ValueError(f"{source} contains duplicate claim id {claim_id}")
        seen.add(claim_id)
        for field in ("path", "text", "severity", "status"):
            value = claim.get(field)
            if not isinstance(value, str) or not value:
                raise ValueError(f"{label} field {field} must be a non-empty string")
        for field in ("line", "column"):
            value = claim.get(field)
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ValueError(f"{label} field {field} must be a positive integer")
        if claim["severity"] not in _SEVERITY_RANK:
            raise ValueError(f"{label} has an invalid severity")
        if claim["status"] not in {"linked", "review", "suppressed"}:
            raise ValueError(f"{label} has an invalid status")
        _string_array(
            claim.get("rules"),
            f"{label} rules",
            require_item=True,
            require_non_blank=True,
            require_unique=True,
        )
        _string_array(
            claim.get("suppression_reasons"),
            f"{label} suppression_reasons",
            require_non_blank=True,
            require_unique=True,
        )
        context = claim.get("context")
        if not isinstance(context, dict):
            raise ValueError(f"{label} context must be an object")
        for field in ("required", "present", "missing"):
            _string_array(
                context.get(field),
                f"{label} context.{field}",
                require_non_blank=True,
                require_unique=True,
            )
        evidence = claim.get("evidence")
        if not isinstance(evidence, list):
            raise ValueError(f"{label} evidence must be an array")
        for anchor_index, anchor in enumerate(evidence):
            anchor_label = f"{label} evidence {anchor_index}"
            if not isinstance(anchor, dict):
                raise ValueError(f"{anchor_label} must be an object")
            for field in ("kind", "target", "status"):
                value = anchor.get(field)
                if not isinstance(value, str) or not value:
                    raise ValueError(
                        f"{anchor_label} field {field} must be a non-empty string"
                    )
            if anchor["kind"] not in _ANCHOR_KINDS:
                raise ValueError(f"{anchor_label} has an invalid kind")
            if anchor["status"] not in _ANCHOR_STATUSES:
                raise ValueError(f"{anchor_label} has an invalid status")
            for field in ("line", "column"):
                value = anchor.get(field)
                if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                    raise ValueError(f"{anchor_label} field {field} must be a positive integer")
            repository_path = anchor.get("repository_path")
            if repository_path is not None and (
                not isinstance(repository_path, str) or not repository_path
            ):
                raise ValueError(
                    f"{anchor_label} field repository_path must be a non-empty string"
                )
            sha256 = anchor.get("sha256")
            if sha256 is not None and (
                not isinstance(sha256, str) or not _SHA256.fullmatch(sha256)
            ):
                raise ValueError(f"{anchor_label} field sha256 must be a SHA-256 digest")
            size_bytes = anchor.get("size_bytes")
            if size_bytes is not None and (
                isinstance(size_bytes, bool)
                or not isinstance(size_bytes, int)
                or size_bytes < 0
            ):
                raise ValueError(
                    f"{anchor_label} field size_bytes must be a non-negative integer"
                )


def compare_ledgers(
    previous: dict[str, Any],
    current: dict[str, Any],
) -> dict[str, Any]:
    validate_ledger(previous, source="previous claim ledger")
    validate_ledger(current, source="current claim ledger")
    previous_claims = {claim["id"]: claim for claim in previous["claims"]}
    current_claims = {claim["id"]: claim for claim in current["claims"]}
    events: list[dict[str, Any]] = []
    stable_claims = 0

    for claim_id in sorted(previous_claims.keys() | current_claims.keys()):
        before = previous_claims.get(claim_id)
        after = current_claims.get(claim_id)
        if before is None:
            events.append(
                _event(
                    "claim-added",
                    after,
                    review_required=after["status"] != "linked",
                    before=None,
                    after=_claim_summary(after),
                )
            )
            continue
        if after is None:
            events.append(
                _event(
                    "claim-removed",
                    before,
                    review_required=False,
                    before=_claim_summary(before),
                    after=None,
                )
            )
            continue

        start = len(events)
        _compare_claim_fields(before, after, events)
        _compare_evidence(before, after, events)
        if len(events) == start:
            stable_claims += 1

    events.sort(key=_event_sort_key)
    by_kind = Counter(event["kind"] for event in events)
    changed_claim_ids = {event["claim_id"] for event in events}
    review_claim_ids = {
        event["claim_id"] for event in events if event["review_required"]
    }
    return {
        "$schema": DRIFT_SCHEMA,
        "schema_version": "1.0",
        "tool": {"name": "ClaimFence", "version": __version__},
        "previous": {
            "tool_version": previous["tool"]["version"],
            "claims": len(previous_claims),
        },
        "current": {
            "tool_version": current["tool"]["version"],
            "claims": len(current_claims),
        },
        "summary": {
            "events": len(events),
            "claims_changed": len(changed_claim_ids),
            "claims_requiring_review": len(review_claim_ids),
            "review_events": sum(event["review_required"] for event in events),
            "stable_claims": stable_claims,
            "event_counts": {kind: by_kind[kind] for kind in EVENT_KINDS},
        },
        "events": events,
        "interpretation": {
            "changed": (
                "A deterministic claim, context, disposition, or evidence-anchor field changed."
            ),
            "review_required": (
                "The current state lost context or evidence, gained an unresolved status "
                "or suppression, increased severity, or changed bound evidence state."
            ),
        },
        "limitations": [
            "Drift is a change signal, not a truth or quality verdict.",
            "A changed local digest establishes different bytes, not weaker evidence.",
            "Same-size byte changes in present-unhashed files cannot be detected.",
            "Claim rewrites normally appear as one removed claim and one added claim.",
            "Tool-version changes can alter lexical matches and should be reviewed separately.",
            "External URLs and recorded commands remain unfetched and unexecuted.",
        ],
    }


def drift_json_report(payload: dict[str, Any]) -> str:
    return json.dumps(payload, indent=2, sort_keys=True)


def drift_text_report(payload: dict[str, Any]) -> str:
    summary = payload["summary"]
    lines = [
        (
            "ClaimFence evidence drift: "
            f"{summary['events']} event(s) across {summary['claims_changed']} claim(s); "
            f"{summary['claims_requiring_review']} claim(s) require review."
        )
    ]
    for event in payload["events"][:20]:
        field = f" {event['field']}" if event.get("field") else ""
        marker = "review" if event["review_required"] else "change"
        lines.append(
            f"  {marker}: {event['kind']}{field} {event['claim_id']} "
            f"{_single_line(event['path'])}"
        )
    remaining = summary["events"] - min(summary["events"], 20)
    if remaining:
        lines.append(f"  ...and {remaining} more drift event(s).")
    return "\n".join(lines)


def drift_github_summary(payload: dict[str, Any]) -> str:
    summary = payload["summary"]
    counts = summary["event_counts"]
    previous_version = payload["previous"]["tool_version"]
    current_version = payload["current"]["tool_version"]
    lines = [
        "## ClaimFence evidence drift",
        "",
        (
            f"**{summary['events']} event(s)** across {summary['claims_changed']} claim(s); "
            f"**{summary['claims_requiring_review']} claim(s) require review**."
        ),
        "",
        (
            f"Ledger tools: {_github_code(previous_version)} → "
            f"{_github_code(current_version)}."
        ),
        "",
        (
            "| Added claims | Removed claims | Changed fields | Evidence added | "
            "Evidence removed | Evidence changed |"
        ),
        "| ---: | ---: | ---: | ---: | ---: | ---: |",
        (
            f"| {counts['claim-added']} | {counts['claim-removed']} | "
            f"{counts['claim-field-changed']} | {counts['evidence-added']} | "
            f"{counts['evidence-removed']} | {counts['evidence-changed']} |"
        ),
    ]
    if payload["events"]:
        lines.extend(["", "### First drift events", ""])
        for event in payload["events"][:20]:
            field = (
                f" · {_github_code(event['field'])}" if event.get("field") else ""
            )
            marker = "review" if event["review_required"] else "change"
            lines.append(
                f"- **{marker.upper()}** {_github_code(event['kind'])}{field} — "
                f"{_github_code(event['path'])} · {_github_code(event['claim_id'])}"
            )
    else:
        lines.extend(["", "No claim or evidence drift was detected."])
    lines.extend(
        [
            "",
            "> Drift identifies changed declarations and evidence bytes; it does not judge truth.",
        ]
    )
    return "\n".join(lines)


def drift_github_output(
    payload: dict[str, Any] | None,
    fail_on: str,
) -> str:
    if payload is None:
        values: dict[str, object] = {
            "drift-configured": "false",
            "drift-events-count": 0,
            "drift-claims-count": 0,
            "drift-review-count": 0,
            "drift-outcome": "not-configured",
        }
    else:
        summary = payload["summary"]
        failed = drift_fails(payload, fail_on)
        values = {
            "drift-configured": "true",
            "drift-events-count": summary["events"],
            "drift-claims-count": summary["claims_changed"],
            "drift-review-count": summary["claims_requiring_review"],
            "drift-outcome": (
                "failed" if failed else "stable" if summary["events"] == 0 else "changed"
            ),
        }
    return "\n".join(f"{name}={value}" for name, value in values.items())


def drift_fails(payload: dict[str, Any], fail_on: str) -> bool:
    if fail_on == "none":
        return False
    if fail_on == "any":
        return payload["summary"]["events"] > 0
    if fail_on == "review":
        return payload["summary"]["review_events"] > 0
    raise ValueError(f"unknown drift threshold: {fail_on}")


def _compare_claim_fields(
    before: dict[str, Any],
    after: dict[str, Any],
    events: list[dict[str, Any]],
) -> None:
    fields = (
        "path",
        "text",
        "rules",
        "severity",
        "status",
        "suppression_reasons",
    )
    for field in fields:
        before_value = before[field]
        after_value = after[field]
        if before_value == after_value:
            continue
        review_required = _field_needs_review(field, before_value, after_value)
        events.append(
            _event(
                "claim-field-changed",
                after,
                review_required=review_required,
                field=field,
                before=before_value,
                after=after_value,
            )
        )

    for field in ("required", "present", "missing"):
        before_value = before["context"][field]
        after_value = after["context"][field]
        if before_value == after_value:
            continue
        before_set = set(before_value)
        after_set = set(after_value)
        review_required = (
            bool(after_set - before_set)
            if field in {"required", "missing"}
            else bool(before_set - after_set)
        )
        events.append(
            _event(
                "claim-field-changed",
                after,
                review_required=review_required,
                field=f"context.{field}",
                before=before_value,
                after=after_value,
            )
        )


def _compare_evidence(
    before: dict[str, Any],
    after: dict[str, Any],
    events: list[dict[str, Any]],
) -> None:
    before_groups = _evidence_groups(before["evidence"])
    after_groups = _evidence_groups(after["evidence"])
    for identity in sorted(before_groups.keys() | after_groups.keys()):
        before_state = before_groups.get(identity)
        after_state = after_groups.get(identity)
        anchor = _anchor_identity_payload(identity)
        if before_state is None:
            events.append(
                _event(
                    "evidence-added",
                    after,
                    review_required=False,
                    field="evidence",
                    anchor=anchor,
                    before=None,
                    after=after_state,
                )
            )
        elif after_state is None:
            events.append(
                _event(
                    "evidence-removed",
                    after,
                    review_required=True,
                    field="evidence",
                    anchor=anchor,
                    before=before_state,
                    after=None,
                )
            )
        elif before_state != after_state:
            events.append(
                _event(
                    "evidence-changed",
                    after,
                    review_required=True,
                    field="evidence",
                    anchor=anchor,
                    before=before_state,
                    after=after_state,
                )
            )


def _field_needs_review(field: str, before: object, after: object) -> bool:
    if field in {"path", "text"}:
        return True
    if field == "severity":
        return _SEVERITY_RANK[str(after)] > _SEVERITY_RANK[str(before)]
    if field == "status":
        return after != "linked"
    if field == "suppression_reasons":
        return bool(set(after) - set(before))
    return False


def _evidence_groups(
    anchors: list[dict[str, Any]],
) -> dict[tuple[str, str, str], list[dict[str, Any]]]:
    grouped: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    for anchor in anchors:
        kind = anchor["kind"]
        repository_path = str(anchor.get("repository_path", ""))
        identity_kind = (
            "local-reference" if kind in {"local-file", "local-path"} else kind
        )
        identity_target = repository_path or anchor["target"]
        identity = (
            identity_kind,
            identity_target,
            repository_path,
        )
        state: dict[str, Any] = {
            key: anchor[key]
            for key in ("kind", "status", "sha256", "size_bytes")
            if key in anchor
        }
        grouped.setdefault(identity, []).append(state)
    for values in grouped.values():
        values.sort(key=lambda value: json.dumps(value, sort_keys=True, separators=(",", ":")))
    return grouped


def _anchor_identity_payload(identity: tuple[str, str, str]) -> dict[str, str]:
    kind, target, repository_path = identity
    payload = {"kind": kind, "target": target}
    if repository_path:
        payload["repository_path"] = repository_path
    return payload


def _event(
    kind: str,
    claim: dict[str, Any],
    *,
    review_required: bool,
    before: object,
    after: object,
    field: str | None = None,
    anchor: dict[str, str] | None = None,
) -> dict[str, Any]:
    event: dict[str, Any] = {
        "kind": kind,
        "claim_id": claim["id"],
        "path": claim["path"],
        "text": claim["text"],
        "review_required": review_required,
        "before": before,
        "after": after,
    }
    if field is not None:
        event["field"] = field
    if anchor is not None:
        event["anchor"] = anchor
    return event


def _claim_summary(claim: dict[str, Any]) -> dict[str, Any]:
    return {
        "rules": claim["rules"],
        "severity": claim["severity"],
        "status": claim["status"],
        "context": claim["context"],
        "evidence_anchors": len(claim["evidence"]),
    }


def _event_sort_key(event: dict[str, Any]) -> tuple[object, ...]:
    anchor = event.get("anchor", {})
    return (
        event["claim_id"],
        _EVENT_ORDER[event["kind"]],
        event.get("field", ""),
        anchor.get("kind", ""),
        anchor.get("target", ""),
        anchor.get("repository_path", ""),
    )


def _string_array(
    value: object,
    label: str,
    *,
    require_item: bool = False,
    require_non_blank: bool = False,
    require_unique: bool = False,
) -> None:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"{label} must be an array of strings")
    if require_item and not value:
        raise ValueError(f"{label} must not be empty")
    if require_non_blank and any(not item.strip() for item in value):
        raise ValueError(f"{label} must not contain empty strings")
    if require_unique and len(value) != len(set(value)):
        raise ValueError(f"{label} must contain unique strings")


def _github_code(value: object) -> str:
    return f"<code>{html.escape(_single_line(value), quote=True)}</code>"


def _single_line(value: object) -> str:
    return "".join(
        character if character >= " " and character != "\x7f" else " "
        for character in str(value)
    )
