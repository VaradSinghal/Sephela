"""Contract tests — validate the live OpenAPI spec against the running app.

Uses ``schemathesis`` to fuzz-test the API against its own OpenAPI schema,
ensuring that:
  1. Every declared endpoint responds with schema-valid responses.
  2. No 500s on well-formed fuzzed input.

Run with: ``pytest tests/test_contracts.py -v``
"""

from __future__ import annotations

import pytest

try:
    import schemathesis
except ImportError:
    pytest.skip("schemathesis not installed", allow_module_level=True)


from app.main import app

# Generate a schema from the live FastAPI app instance.
schema = schemathesis.from_asgi("/api/v1/openapi.json", app=app)


@schema.parametrize()
def test_api_contracts(case: schemathesis.Case) -> None:
    """Every endpoint must return a response matching its OpenAPI schema.

    Schemathesis generates random valid payloads per-endpoint and validates
    that the response conforms to the declared schema. Auth-gated endpoints
    will return 401, which is an expected response code.
    """
    response = case.call_asgi()

    # We don't treat 401/403 as failures — those are expected for
    # auth-gated endpoints when no token is supplied.
    if response.status_code in (401, 403):
        return

    case.validate_response(response)
