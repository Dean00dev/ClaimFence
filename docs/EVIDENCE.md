# Verification evidence

ClaimFence's executable verification is the standard-library suite in `tests/`.

Run it from the repository root:

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

CI repeats the suite on each supported Python version. The workflow run is the durable
receipt for a particular commit; this file is only the reproduction map.

The suite includes adversarial cases for soft-wrapped negation, universal-negative claims,
repository-root escapes, missing references, evidence-shaped filename examples, stable
claim identifiers, suppression reasons, deterministic report bytes, local-file digests,
and document-derived HTML injection.

Generate the visual and machine-readable reports exercised by the suite:

```bash
PYTHONPATH=src python -m claimfence examples/unsafe-readme.md \
  --root . --fail-on none \
  --ledger-output claimfence-ledger.json \
  --html-output claimfence-map.html
```

Its existence demonstrates the `CF005` path-integrity floor. It is not, by itself, proof
that a claim is true; readers should inspect the referenced test and CI run.
