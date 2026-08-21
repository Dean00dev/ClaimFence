# Security policy

ClaimFence processes untrusted Markdown locally. Please report path traversal, unintended
file access, command execution, output injection, or CI annotation injection privately
through GitHub's security advisory feature for this repository.

Do not include confidential documents, credentials, personal data, or active exploit code
in a public issue. Ordinary false positives and missed phrases are correctness bugs and may
be reported publicly.

All v0.x releases are alpha software. ClaimFence is not a security control, and a clean
scan or unchanged drift receipt is not a security assessment.

When `--root` is supplied, scan inputs are constrained after symbolic-link resolution.
Comparison ledgers are treated as untrusted structured input and capped at 32 MiB, but
ClaimFence does not authenticate their provenance. Source a gate ledger from a protected
revision or trusted workflow artifact. The composite Action and pre-commit hook place scan
paths after the CLI option terminator so a dash-prefixed path is not interpreted as an
option.
