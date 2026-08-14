# Verification evidence

ClaimFence's executable verification is the standard-library suite in `tests/`.

Run it from the repository root:

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

CI repeats the suite on each supported Python version. The workflow run is the durable
receipt for a particular commit; this file is only the reproduction map.

Its existence demonstrates the `CF005` path-integrity floor. It is not, by itself, proof
that a claim is true; readers should inspect the referenced test and CI run.
