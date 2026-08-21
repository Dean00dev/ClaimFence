# Evidence Map contract

ClaimFence's Evidence Map is a deterministic inventory of the assurance language matched
by the active rule set. It records both findings and claims that have the lexical context
their rule requires.

Generate both portable forms from one scan:

```bash
claimfence README.md docs --fail-on none \
  --ledger-output claimfence-ledger.json \
  --html-output claimfence-map.html
```

The HTML file is self-contained and can be opened locally or uploaded as a workflow
artifact. It loads no fonts, scripts, styles, or analytics from the network. The JSON file
follows [`schema/claim-ledger-v1.schema.json`](../schema/claim-ledger-v1.schema.json).

## Statuses

The map deliberately has no score or percentage.

| Status | Exact meaning |
|---|---|
| `linked` | Every matched rule for the claim found its required lexical context. Evidence context includes at least one command, URL, or repository-local reference. |
| `review` | At least one matched rule is missing required scope or evidence context. |
| `suppressed` | Every otherwise-reviewable match was suppressed by an inline directive carrying a non-empty reason. The reason is retained in the ledger. |

`linked` is not a synonym for verified. It does not establish that the claim is true, the
scope is appropriate, or the evidence is relevant, current, authentic, independently
produced, or sufficient.

## Evidence anchors

For each claim, the configurable context radius is searched for concrete anchors:

- reproduction commands are recorded with `status: not-executed`;
- external HTTP or HTTPS URLs are recorded with `status: not-fetched`;
- repository-local paths are constrained to the selected root and marked `present`,
  `missing`, `directory`, or `outside-root`;
- present regular files up to 16 MiB receive their byte size and SHA-256 digest while a
  ledger or HTML map is being written;
- larger files are marked `present-unhashed` to bound report-generation work.

Hashing proves only that a particular byte sequence was observed. A digest does not make
the bytes good evidence. Normal scans that do not request a ledger or map do not read
linked evidence file contents.

## Stability and baselines

Claim identifiers are derived from the repository-relative document path, normalized claim
text, and the occurrence number only when identical text appears more than once in one file.
Rewrapping a paragraph or inserting unrelated prose does not change its identifier. Rewriting
the claim does; inserting another identical claim before a duplicate can change duplicate
occurrence identifiers.

The ledger is intentionally generated from the complete matched-claim inventory. A
fingerprint baseline can remove a finding from gate output, but it does not rewrite that
claim as `linked` or hide it from the map. Baselines manage migration noise; they are not
evidence.

The output has no timestamp, host name, repository owner, branch name, or network-derived
field. Identical scanned bytes, configuration, repository-local evidence bytes, and tool
version produce identical ledger bytes.

Starting in v0.5, a saved ledger can be compared with a later scan to produce a separate
deterministic Evidence Drift receipt. See the
[Evidence Drift contract](EVIDENCE_DRIFT.md) for event identities, gate semantics, and the
trusted-ledger boundary.

## Optional signing with GitHub attestations

The ledger is suitable as a custom predicate for GitHub's general-purpose attestation
Action. Signing binds the exact ledger bytes and workflow identity to a chosen build
artifact; it does not upgrade ClaimFence's lexical findings into factual verification.

```yaml
permissions:
  contents: read
  id-token: write
  attestations: write
  artifact-metadata: write

steps:
  - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4.4.0
  - uses: Dean00dev/ClaimFence@v0.5.1
    with:
      paths: README.md docs
      fail-on: none
      ledger-output: claimfence-ledger.json
  - uses: actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6 # v4.2.2
    with:
      subject-path: dist/project.tar.gz
      predicate-type: https://raw.githubusercontent.com/Dean00dev/ClaimFence/v0.5.1/schema/claim-ledger-v1.schema.json
      predicate-path: claimfence-ledger.json
```

The example pins the attestation Action to the reviewed v4.2.2 commit. Re-check that pin
against the upstream release before adopting the pattern.

## Security boundary

Scanned Markdown and comparison ledgers are untrusted input. Under v0.5.1's packaged scan
and report paths, ClaimFence does not execute embedded code or commands, evaluate templates,
fetch URLs, or load repository modules. Explicit repository roots constrain requested and
discovered scan files after symbolic-link resolution. Document-derived HTML and
workflow-summary values are escaped. Comparison ledgers are structurally validated and
limited to 32 MiB. Inspect the
[`scanner`](../src/claimfence/scanner.py) and
[`reporters`](../src/claimfence/reporters.py) plus the
[`drift comparator`](../src/claimfence/drift.py), then reproduce the adversarial fixtures with
`PYTHONPATH=src python -m unittest discover -s tests -v`. This boundary covers the cited
v0.5.1 code and tests, not modified forks or future releases.

An author can still evade a lexical rule, link irrelevant material, create a placeholder
file, or provide a misleading suppression reason. The map makes those declarations visible;
it cannot make the author honest.
