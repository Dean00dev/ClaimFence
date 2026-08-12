# Reference gateway

## Evidence and verification

Under version 0.3 with the included replay fixtures, the gateway blocks the tested
malformed-token cases. Reproduce with `pytest tests/test_gateway.py` and inspect the
[campaign report](reports/v0.3.md).

## Limitations

This prototype does not establish security against untested attacks or modified deployments.
