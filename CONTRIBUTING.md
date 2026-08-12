# Contributing to ClaimFence

ClaimFence improves through counterexamples. A useful rule contribution includes both the
claim it should catch and bounded prose it must leave alone.

## Before opening a pull request

1. Add or update fixtures for the intended behavior.
2. Add a regression test for every fixed false positive or false negative.
3. Run `PYTHONPATH=src python -m unittest discover -s tests -v`.
4. Run `PYTHONPATH=src python -m claimfence . --no-color`.
5. Document rule semantics or configuration changes.

New dependencies require a design justification. Runtime dependencies are not accepted
merely for convenience.

## Rule design

- Prefer a narrow falsifiable pattern over broad vocabulary matching.
- Do not infer that a matched claim is false.
- Preserve negation, code-fence, suppression, baseline, JSON, GitHub, and SARIF behavior.
- Treat false-positive reduction as a feature, not a cosmetic change.

By participating, you agree to follow [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
