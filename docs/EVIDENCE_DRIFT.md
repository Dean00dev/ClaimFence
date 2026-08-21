# Evidence Drift contract

Evidence Drift answers a narrow question: **what changed between a previous ClaimFence
claim ledger and the current scan?**

It compares deterministic declarations already present in the ledgers. It does not fetch a
URL, execute a command, inspect version-control history, authenticate the earlier ledger,
or judge whether evidence is true, relevant, current, or sufficient.

## Generate a receipt

Create a ledger for a trusted base revision or completed workflow:

```bash
claimfence README.md docs --root . --fail-on none \
  --ledger-output previous-ledger.json
```

On a later revision, scan the same boundary and compare it:

```bash
claimfence README.md docs --root . --fail-on none \
  --compare-ledger previous-ledger.json \
  --ledger-output current-ledger.json \
  --drift-output claimfence-drift.json \
  --fail-on-drift review
```

The drift receipt follows
[`schema/evidence-drift-v1.schema.json`](../schema/evidence-drift-v1.schema.json). It has no
timestamp, host name, branch name, or network-derived field. Equal inputs produce equal
receipt bytes.

`--compare-ledger` enables comparison. `--drift-output` writes the JSON receipt, while a
normal text report includes a concise drift section. `--ledger-output` is optional during
comparison but is useful for retaining the current state. ClaimFence rejects output paths
that would overwrite the comparison ledger and rejects a drift receipt path shared with
another output.

## Event model

| Event | Meaning | Review classification |
|---|---|---|
| `claim-added` | A stable claim identifier exists only in the current ledger | Yes when its current status is not `linked` |
| `claim-removed` | A stable claim identifier exists only in the previous ledger | No; use the `any` gate when removal should halt the workflow |
| `claim-field-changed` | A consumed claim, context, rule, severity, disposition, or suppression field changed | Directional: lost context, increased severity, unresolved status, changed text/path, or added suppression requires review |
| `evidence-added` | A normalized anchor identity exists only in the current ledger | No |
| `evidence-removed` | A normalized anchor identity exists only in the previous ledger | Yes |
| `evidence-changed` | The same anchor changed kind, resolution status, byte size, or recorded SHA-256 digest | Yes |

One claim can produce several events. `claims_changed` counts distinct affected claim
identifiers; `review_events` counts individual review-classified events; and
`claims_requiring_review` counts distinct claims with at least one such event.

## Gates

| Gate | Exit code `1` when |
|---|---|
| `--fail-on-drift none` | Never because of drift; the receipt still records events |
| `--fail-on-drift review` | At least one event carries `review_required: true` |
| `--fail-on-drift any` | At least one drift event exists |

The ordinary finding gate and the drift gate are independent. The command returns `1` when
either configured gate fires and `2` when comparison input or configuration is invalid.

## Stability boundary

Claims are joined by their `CLM-…` identifier. Rewrapping ordinary prose and inserting an
unrelated block do not change that identifier. A rewritten claim normally appears as one
removed claim and one added claim, so use `any` if wording changes should halt the workflow.

Source line and column are deliberately ignored. Repository-local anchors use a resolved
repository-relative identity where available, which makes `examples/bounded-readme.md` and
`./examples/bounded-readme.md` equivalent. Commands and external URLs use their recorded
targets. Changing the bytes at the same local identity produces `evidence-changed`.

Both ledger tool versions are recorded in the receipt and workflow summary. A version
difference is not itself an event because rule upgrades can intentionally change the
inventory; review version transitions separately.

## Trust boundary

A comparison is only as trustworthy as its previous ledger. Keep that ledger on a protected
base revision, download it from a trusted workflow run, or bind it to an artifact with an
attestation. Do not let an untrusted change replace both the documentation and its own
comparison ledger.

ClaimFence validates the v1 schema version, producer name, claim identifiers, consumed field
types, dispositions, evidence states, and digest shape before comparison. Input is capped at
32 MiB. These checks reject malformed data; they do not establish provenance or honesty.

The GitHub Action accepts the same options:

```yaml
- uses: Dean00dev/ClaimFence@v0.5.1
  id: claimfence
  with:
    paths: README.md docs
    fail-on: warning
    compare-ledger: previous-ledger.json
    fail-on-drift: review
    ledger-output: current-ledger.json
    drift-output: claimfence-drift.json
```

It appends the comparison to the workflow summary and exposes `drift-configured`,
`drift-events-count`, `drift-claims-count`, `drift-review-count`, and `drift-outcome` for
later steps.

## Limitations and interpretation boundary

- Different bytes do not imply weaker evidence.
- Equal bytes do not imply current, relevant, or sufficient evidence.
- Files above 16 MiB have size but no digest, so a same-size byte change is not observable.
- An added linked claim is still a lexical disposition, not a factual conclusion.
- A stable receipt covers only the selected paths, configuration, ledger fields, and tool
  behavior.
- External URLs remain unfetched, and commands remain unexecuted.
