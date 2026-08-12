# Example gateway

## Verification

Under version 0.3 with the included malformed-token fixtures, the gateway blocks the tested
cases. Reproduce with `pytest tests/test_gateway.py` and inspect the
[campaign report](reports/v0.3.md).

## Limitations

This prototype does not establish security against untested inputs or modified deployments.
