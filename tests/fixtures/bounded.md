# Reference gateway

## Evidence and verification

Under version 0.3 with the included replay fixtures, the gateway blocks the tested
malformed-token cases. Reproduce with `python -m unittest discover -s tests -v` and inspect
the [verification receipt](../../docs/EVIDENCE.md).

## Limitations

This prototype does not establish security against untested attacks or modified deployments.
