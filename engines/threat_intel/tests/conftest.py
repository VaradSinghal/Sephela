"""Shared fixtures — a fake HTTP layer so no test ever touches the network.

Providers are exercised through ``httpx.MockTransport`` rather than by stubbing
the provider classes, so the tests cover the real request construction (headers,
form bodies, URL/hash path building) and the real status-code → error mapping,
not a mock of it.
"""

from __future__ import annotations

from collections.abc import Callable

import httpx
import pytest

Handler = Callable[[httpx.Request], httpx.Response]


@pytest.fixture
def make_client() -> Callable[[Handler], httpx.AsyncClient]:
    """Build an AsyncClient whose every request is served by ``handler``."""

    def _factory(handler: Handler) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.MockTransport(handler))

    return _factory


@pytest.fixture
def json_client(make_client: Callable[[Handler], httpx.AsyncClient]):  # type: ignore[no-untyped-def]
    """Serve one fixed JSON body (and status) for every request."""

    def _factory(payload: object, status: int = 200) -> httpx.AsyncClient:
        return make_client(lambda _request: httpx.Response(status, json=payload))

    return _factory


@pytest.fixture
def recording_client(make_client: Callable[[Handler], httpx.AsyncClient]):  # type: ignore[no-untyped-def]
    """Serve a fixed body while recording the requests that were made."""

    def _factory(
        payload: object, status: int = 200
    ) -> tuple[httpx.AsyncClient, list[httpx.Request]]:
        seen: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(request)
            return httpx.Response(status, json=payload)

        return make_client(handler), seen

    return _factory
