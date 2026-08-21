# Changelog

## 0.6.0 - 2026-08-21

- Add optional stable claim anchors with the one-line
  `<!-- claimfence-id: ... -->` directive.
- Preserve a claim's deterministic ledger identity across deliberate wording changes and
  Markdown file moves, allowing Evidence Drift to emit field-level review events.
- Record the author-selected value as `stable_id` in ledgers, drift events, and Evidence
  Map source labels.
- Reject malformed, duplicate, dangling, displaced, and multi-claim anchor ambiguity; ignore
  directive-shaped examples inside fenced, indented, or inline code.
- Keep v1 ledger comparison compatible with older receipts that have no `stable_id`.

## 0.5.1 - 2026-08-21

- Correct release provenance after the published `v0.5.0` tag targeted the prior v0.4
  source instead of the verified Evidence Drift implementation.
- Point install examples and immutable ledger and drift schema identifiers at the
  corrective `v0.5.1` release.
- Include the Windows-safe byte fixtures used by the cross-platform evidence-digest tests.

## 0.5.0 - 2026-08-20

- Add deterministic Evidence Drift comparison between a saved v1 claim ledger and the
  current scan.
- Emit a versioned JSON drift receipt with claim, context, disposition, and evidence-anchor
  events plus explicit review classifications.
- Add `none`, `review`, and `any` drift gates to the CLI and composite GitHub Action.
- Expose drift state, event count, affected-claim count, review count, and outcome as Action
  outputs and in the workflow summary.
- Normalize repository-local anchor identity so cosmetic link spelling and source-coordinate
  movement do not create drift while recorded digest and size changes do.
- Validate and bound untrusted comparison ledgers before use and escape ledger-derived
  workflow-summary values.
- Refuse output-path collisions that could overwrite a trusted comparison ledger or replace
  another report with a drift receipt.
- Reject explicit scan paths and Markdown symbolic links that escape a selected repository
  root.
- Treat composite-Action and pre-commit scan paths strictly as positional arguments after
  the option terminator.
- Reject blank custom evidence terms and boolean context radii instead of allowing
  fail-open or ambiguous configuration.
- Expand CI through Python 3.14, add macOS and Windows boundary coverage, and smoke-test the
  built wheel and drift-enabled composite Action.

## 0.4.0 - 2026-08-14

- Add a deterministic claim ledger covering both reviewable and context-linked claims.
- Add a self-contained interactive HTML Evidence Map with no external assets or requests.
- Map each claim to its required, present, and missing context plus nearby commands, URLs,
  and repository-local evidence anchors.
- Hash present local evidence files up to 16 MiB only when a ledger or map is requested.
- Preserve reasoned suppression text in the claim ledger.
- Add versioned JSON Schema for machine consumers and custom attestation predicates.
- Expose claim-status and evidence-anchor counts as GitHub Action outputs.
- Stop treating path-shaped inline-code examples as evidence without an evidence cue.
- Recognize wrapped, formatted, and nested epistemic negation without silencing universal
  negative assurance claims.
- Recognize bold test and residual-risk subsection labels and reduce one-off document
  structure noise.
- Add adversarial tests for report determinism, HTML injection, evidence digests, suppression
  reasons, and example-path false positives.

## 0.3.0 - 2026-08-14

- Reflow soft-wrapped Markdown into source-mapped logical blocks before rule evaluation.
- Keep rule results and fingerprints stable when prose is wrapped at different widths.
- Distinguish epistemic limitations from universal-negative assurance claims.
- Add `CF005` to validate repository-local evidence links and command paths.
- Require concrete evidence anchors instead of accepting evidence-shaped words alone.
- Add repository-root selection plus one-pass JSON and SARIF artifact outputs.
- Report `outcome=report-only` when no failure threshold is configured.
- Document the reference-integrity floor: existing files may still be empty or irrelevant.
- Use canonical repository casing in clone URLs, badges, and project metadata.

## 0.2.0 - 2026-08-14

- Add a concise Markdown scan summary to the GitHub Actions job summary.
- Expose file, severity, suppression, baseline, and threshold outcome Action outputs.
- Expose custom configuration and fingerprint baselines as Action inputs.
- Use one runtime version source across CLI, JSON, and SARIF reports.
- Pin third-party actions in ClaimFence's own CI to reviewed commit SHAs.
- Expand the test suite to cover summaries, outputs, report-only mode, and version metadata.

## 0.1.0 - 2026-08-12

- Initial deterministic Markdown scanner.
- Four phrase rules and two document-structure rules.
- Text, JSON, GitHub annotation, and SARIF output.
- Reasoned next-line suppressions and fingerprint baselines.
- Zero runtime dependencies.
- Composite GitHub Action and pre-commit hook metadata.
