"""Shared HTTP plumbing for providers.

Every feed fails in the same handful of ways, and each way needs a *different*
reaction from the pipeline, so the mapping lives here once instead of in five
provider modules:

- **404 / "no results"** → not an error. The feed answered; it has no record.
  Returning ``None`` lets the provider emit a ``Verdict.unknown`` result, which
  is real evidence (an unknown hash is more suspicious than a known-clean one).
- **429 / 403-with-quota** → ``RateLimitedError``. Retrying immediately makes it
  worse; the caller backs the whole provider off.
- **5xx / timeout / connection error** → ``ProviderUnavailableError``, which
  feeds the circuit breaker.
- **malformed JSON** → ``ProviderError``. Provider responses are untrusted input
  (docs/architecture/09-security.md); a feed returning an HTML error page must
  not raise something the pipeline doesn't expect.
"""

from __future__ import annotations

from typing import Any

import httpx

from sephela_threat_intel.base import (
    ProviderError,
    ProviderUnavailableError,
    RateLimitedError,
)

#: Cap on the response bytes parsed per lookup. VirusTotal file reports can
#: exceed a megabyte of per-engine detail we never read.
MAX_RESPONSE_BYTES = 2 * 1024 * 1024


async def request_json(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    *,
    provider: str,
    headers: dict[str, str] | None = None,
    params: dict[str, str] | None = None,
    data: dict[str, str] | None = None,
) -> dict[str, Any] | None:
    """Perform one provider call, returning parsed JSON or None for "no record"."""
    try:
        response = await client.request(
            method, url, headers=headers, params=params, data=data
        )
    except httpx.TimeoutException as exc:
        raise ProviderUnavailableError(f"{provider}: request timed out") from exc
    except httpx.HTTPError as exc:
        raise ProviderUnavailableError(f"{provider}: {type(exc).__name__}: {exc}") from exc

    if response.status_code == 404:
        return None
    if response.status_code == 429:
        raise RateLimitedError(f"{provider}: rate limited (HTTP 429)")
    if response.status_code in (401, 403):
        # Distinguishing a bad key from an exhausted quota is not possible from
        # the status alone; both mean "stop calling this provider".
        raise RateLimitedError(
            f"{provider}: rejected credentials or quota (HTTP {response.status_code})"
        )
    if response.status_code >= 500:
        raise ProviderUnavailableError(f"{provider}: upstream error (HTTP {response.status_code})")
    if response.status_code >= 400:
        raise ProviderError(f"{provider}: unexpected HTTP {response.status_code}")

    body = response.content
    if len(body) > MAX_RESPONSE_BYTES:
        raise ProviderError(f"{provider}: response exceeded {MAX_RESPONSE_BYTES} bytes")

    try:
        payload = response.json()
    except ValueError as exc:
        raise ProviderError(f"{provider}: response was not valid JSON") from exc
    if not isinstance(payload, dict):
        raise ProviderError(f"{provider}: expected a JSON object, got {type(payload).__name__}")
    return payload


def clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return max(low, min(high, value))


def str_list(value: Any, *, limit: int = 20) -> list[str]:
    """Coerce an untrusted JSON value into a bounded list of strings."""
    if isinstance(value, str):
        return [value]
    if not isinstance(value, list):
        return []
    out: list[str] = []
    for item in value:
        if isinstance(item, str) and item.strip():
            out.append(item.strip()[:128])
        if len(out) >= limit:
            break
    return out
