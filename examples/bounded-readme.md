# Example gateway

## Verification

Under version 0.3 with the included malformed-token fixtures, the gateway blocks the tested
cases. Reproduce with `python -m unittest discover -s tests -v` and inspect the
[verification receipt](../docs/EVIDENCE.md).

## Limitations

This prototype does not establish security against untested inputs or modified deployments.
