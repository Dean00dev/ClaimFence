# Changelog

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
