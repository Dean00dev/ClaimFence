<p align="center">
  <img src="assets/claimfence-mark.svg" width="112" alt="ClaimFence shield and evidence boundary mark">
</p>

<h1 align="center">ClaimFence</h1>

<p align="center"><strong>A deterministic linter for evidence-bound claims in technical documentation.</strong></p>

<p align="center">
  <a href="https://github.com/Dean00dev/ClaimFence/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/Dean00dev/ClaimFence/actions/workflows/ci.yml/badge.svg"></a>
  <img alt="Python 3.11+" src="https://img.shields.io/badge/python-3.11%2B-1678c2">
  <a href="LICENSE"><img alt="MIT licence" src="https://img.shields.io/badge/licence-MIT-00b4d8"></a>
  <img alt="No runtime dependencies" src="https://img.shields.io/badge/runtime%20dependencies-0-20c997">
</p>

Technical projects often make their strongest claims in the least tested file: the README.
ClaimFence scans Markdown for assurance language and checks whether nearby text exposes
scope, evidence, limitations, or a reproduction path.

It does **not** decide whether a claim is true. It finds claims whose documentation does
not show readers how to evaluate them.

## The difference it looks for

```diff
- The gateway prevents attacks and is production-ready.
+ Under v0.3 with the included malformed-token fixtures, the gateway blocks the
+ tested cases. Reproduce with `PYTHONPATH=src python -m unittest discover -s tests -v`;
+ see the [verification evidence](docs/EVIDENCE.md).
+ This does not establish security against untested inputs or modified deployments.
```

ClaimFence turns the first form into an actionable finding. The second form names a
version, test space, reproduction command, evidence location, and limitation.

## Quick start

ClaimFence requires Python 3.11 or later and has no runtime dependencies.

```bash
git clone https://github.com/Dean00dev/ClaimFence.git
cd ClaimFence
python -m pip install -e .
claimfence README.md docs
```

Example output:

```text
README.md:18:21: warning CF002 assurance language lacks nearby evidence or scope
  claim: The gateway is production-ready.
  fix:   Add a test/report link and state the version, configuration, or conditions covered.
ClaimFence scanned 1 file(s): 0 error(s), 1 warning(s), 0 info.
```

Exit code `1` means the configured threshold was reached. Exit code `2` means the scan
could not run because its input or configuration was invalid.

## GitHub Action

```yaml
name: ClaimFence

on:
  pull_request:
  push:

permissions:
  contents: read

jobs:
  claims:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4.4.0
      - uses: Dean00dev/ClaimFence@v0.3.0
        id: claimfence
        with:
          paths: README.md docs
          fail-on: warning
```

The action emits native file-and-line annotations and a Markdown workflow summary. It also
exposes stable outputs for follow-on steps:

| Output | Meaning |
|---|---|
| `files-scanned` | Markdown files examined |
| `findings-count` | Findings remaining after baseline filtering |
| `error-count`, `warning-count`, `info-count` | Findings by severity |
| `suppressed-count`, `baselined-count` | Findings intentionally omitted |
| `outcome` | `passed`, `failed`, or `report-only` at the configured threshold |

Existing projects can supply the same config and baseline used by the CLI:

```yaml
      - uses: Dean00dev/ClaimFence@v0.3.0
        with:
          paths: README.md docs
          config: .claimfence.toml
          baseline: .claimfence-baseline.json
```

For security-sensitive workflows, replace version tags with the full commit SHA you have
reviewed. ClaimFence can also produce JSON and SARIF from the same scan used for
annotations:

```bash
claimfence . --fail-on none \
  --json-output claimfence.json \
  --sarif-output claimfence.sarif
```

With `fail-on: none`, the Action returns success so reports can be uploaded, but its
`outcome` is `report-only`—never `passed`. A successful report-only workflow proves that
the scan ran, not that the documentation had zero findings.

## What it checks

| Rule | Severity | Question |
|---|---:|---|
| `CF001` | Error | Does the document make an absolute assurance claim? |
| `CF002` | Warning | Does assurance language lack nearby scope or evidence? |
| `CF003` | Warning | Does a universal, zero-result, or universal-negative claim omit its boundary and evidence? |
| `CF004` | Info | Does a test-result claim omit a reproduction path? |
| `CF005` | Warning | Does a local evidence link or command path fail repository-local resolution? |
| `CF101` | Warning | Do assurance claims appear without a limitations section? |
| `CF102` | Warning | Do assurance claims appear without a verification section? |

ClaimFence ignores fenced code blocks and inline code. Epistemic limitations such as
“cannot determine whether…” suppress a nested assurance phrase; universal negatives such
as “never sends…” remain reviewable claims. See the complete
[rule reference](docs/RULES.md) and [design boundaries](docs/DESIGN.md).

## Configuration

Create `.claimfence.toml` in the repository root:

```toml
[claimfence]
fail_on = "warning"
context_blocks = 1
exclude = ["vendor/**", "generated/**"]
disabled_rules = []
extra_evidence_terms = ["assurance receipt"]
```

Context is measured in source-mapped logical Markdown blocks rather than physical lines,
so ordinary prose rewrapping does not change rule outcomes or fingerprints. The v0.2
`context_lines` key remains accepted for compatibility but is deprecated.

A specific false positive can be suppressed only with an inline reason:

```markdown
<!-- claimfence-disable-next-line CF002: Secure Gateway is the upstream product name -->
The Secure Gateway API accepts a token.
```

For an existing documentation estate, create a fingerprint baseline and reject only new
findings:

```bash
claimfence . --write-baseline .claimfence-baseline.json
claimfence . --baseline .claimfence-baseline.json
```

## Verification

Run the standard-library test suite:

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

Then make ClaimFence scan its own documentation:

```bash
PYTHONPATH=src python -m claimfence . --no-color
```

The CI workflow repeats both commands across Python 3.11, 3.12, and 3.13 and smoke-tests
the bundled action.

## Limitations and non-goals

- ClaimFence is lexical and deterministic; it does not understand truth, intent, or the
  full semantics of prose. It reflows ordinary Markdown paragraphs before matching but is
  not a complete CommonMark parser.
- Evidence must have a concrete anchor such as a command, URL, or repository-local path;
  words such as “report” or “tested” are not sufficient by themselves.
- `CF005` establishes only reference integrity: the local path exists and stays inside the
  selected repository root. An empty, irrelevant, stale, or fabricated file can still
  satisfy that check. External URLs are not fetched or authenticated.
- Nearby evidence may still be weak or unrelated. A clean scan is not a factual audit.
- A finding is a review prompt, not proof that the underlying system is unsafe.
- Rule coverage is intentionally narrow in v0.3.0. Synonyms and domain-specific claims can
  be missed.
- English is the only supported prose language in this release.
- Markdown rendered from templates or generated after the scan is outside the tested path.

## Provenance

ClaimFence was conceived and directed by Dean Egan and implemented through an
AI-assisted build workflow. Its design follows one principle: **a claim should
expose the boundary of the evidence supporting it.**

For v0.3.0, [runtime dependencies are empty](pyproject.toml) and the executable scan path
is inspectable in [`src/claimfence`](src/claimfence). Scanned documents are processed on
the machine or CI runner invoking the command.

## Contributing

False-positive reductions, carefully scoped new rules, and adversarial fixtures are
welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request. Report
security-sensitive problems through [SECURITY.md](SECURITY.md).

## Licence

MIT. See [LICENSE](LICENSE).
