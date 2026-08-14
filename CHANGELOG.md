# Changelog

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
