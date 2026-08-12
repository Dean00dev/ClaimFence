<p align="center">
  <img src="assets/claimfence-mark.svg" width="112" alt="ClaimFence shield and evidence boundary mark">
</p>

<h1 align="center">ClaimFence</h1>

<p align="center"><strong>A deterministic linter for evidence-bound claims in technical documentation.</strong></p>

<p align="center">
  <a href="https://github.com/Dean00dev/claimfence/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/Dean00dev/claimfence/actions/workflows/ci.yml/badge.svg"></a>
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
+ tested cases. Reproduce with `pytest tests/test_gateway.py`; see the campaign report.
+ This does not establish security against untested inputs or modified deployments.
```

ClaimFence turns the first form into an actionable finding. The second form names a
version, test space, reproduction command, evidence location, and limitation.

## Quick start

ClaimFence requires Python 3.11 or later and has no runtime dependencies.

```bash
git clone https://github.com/Dean00dev/claimfence.git
cd claimfence
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
      - uses: actions/checkout@v4
      - uses: Dean00dev/ClaimFence@v0.1.0
        with:
          paths: README.md docs
          fail-on: warning
```

The action emits native file-and-line annotations. ClaimFence can also produce JSON or
SARIF for other automation:

```bash
claimfence . --format json --output claimfence.json
claimfence . --format sarif --output claimfence.sarif
```

## What it checks

| Rule | Severity | Question |
|---|---:|---|
| `CF001` | Error | Does the document make an absolute assurance claim? |
| `CF002` | Warning | Does assurance language lack nearby scope or evidence? |
| `CF003` | Warning | Does a universal or zero-result claim omit its test conditions? |
| `CF004` | Info | Does a test-result claim omit a reproduction path? |
| `CF101` | Warning | Do assurance claims appear without a limitations section? |
| `CF102` | Warning | Do assurance claims appear without a verification section? |

ClaimFence ignores fenced code blocks, inline code, and negated claims. See the complete
[rule reference](docs/RULES.md) and [design boundaries](docs/DESIGN.md).

## Configuration

Create `.claimfence.toml` in the repository root:

```toml
[claimfence]
fail_on = "warning"
context_lines = 3
exclude = ["vendor/**", "generated/**"]
disabled_rules = []
extra_evidence_terms = ["assurance receipt"]
```

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
  full semantics of prose.
- Nearby evidence language may be weak, irrelevant, stale, or fabricated. A clean scan is
  not a factual audit.
- A finding is a review prompt, not proof that the underlying system is unsafe.
- Rule coverage is intentionally narrow in v0.1.0. Synonyms and domain-specific claims can
  be missed.
- English is the only supported prose language in this release.
- Markdown rendered from templates or generated after the scan is outside the tested path.

## Provenance

ClaimFence was conceived and directed by Dean Egan and implemented through an
AI-assisted build workflow. Its design follows one principle: **a claim should
expose the boundary of the evidence supporting it.**

No model API is used at runtime. Scanned documents stay on the machine or CI runner where
the command executes.

## Contributing

False-positive reductions, carefully scoped new rules, and adversarial fixtures are
welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request. Report
security-sensitive problems through [SECURITY.md](SECURITY.md).

## Licence

MIT. See [LICENSE](LICENSE).
