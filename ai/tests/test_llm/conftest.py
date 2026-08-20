"""A fake HTTP layer for the provider adapters — no test touches the network.

Same approach as ``engines/threat_intel/tests/conftest.py``: drive the adapters
through ``httpx.MockTransport`` rather than stubbing the adapter classes, so the
tests cover the real request construction — headers, payload shape, JSON-mode flag —
and the real response parsing, instead of a mock of both.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import httpx
import pytest

Handler = Callable[[httpx.Request], httpx.Response]


@pytest.fixture
def install_transport(monkeypatch: pytest.MonkeyPatch) -> Callable[[Handler], list[httpx.Request]]:
    """Route every adapter's HTTP client through ``handler``; return recorded requests.

    Patches the adapters' shared client builder, so the adapter keeps its own base
    URL and headers — the parts worth asserting on.
    """

    def _install(handler: Handler) -> list[httpx.Request]:
        seen: list[httpx.Request] = []

        def _recording(request: httpx.Request) -> httpx.Response:
            seen.append(request)
            return handler(request)

        def _build(base_url: str, headers: dict[str, str], timeout_s: float) -> httpx.AsyncClient:
            return httpx.AsyncClient(
                base_url=base_url,
                headers=headers,
                timeout=httpx.Timeout(timeout_s, connect=10.0),
                transport=httpx.MockTransport(_recording),
            )

        monkeypatch.setattr("ai.llm.adapters._build_client", _build)
        return seen

    return _install


@pytest.fixture
def openai_style_response() -> Callable[..., dict[str, Any]]:
    """An OpenAI/OpenRouter-shaped chat completion body."""

    def _build(
        content: str = '{"ok": true}',
        model: str = "anthropic/claude-opus-5",
        prompt_tokens: int = 100,
        completion_tokens: int = 25,
        finish_reason: str = "stop",
    ) -> dict[str, Any]:
        return {
            "id": "chatcmpl-1",
            "model": model,
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": content},
                    "finish_reason": finish_reason,
                }
            ],
            "usage": {
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "total_tokens": prompt_tokens + completion_tokens,
            },
        }

    return _build


@pytest.fixture
def anthropic_style_response() -> Callable[..., dict[str, Any]]:
    """An Anthropic Messages API body."""

    def _build(
        content: str = '{"ok": true}',
        model: str = "claude-opus-5",
        input_tokens: int = 100,
        output_tokens: int = 25,
        stop_reason: str = "end_turn",
    ) -> dict[str, Any]:
        return {
            "id": "msg_1",
            "type": "message",
            "role": "assistant",
            "model": model,
            "content": [{"type": "text", "text": content}],
            "stop_reason": stop_reason,
            "usage": {"input_tokens": input_tokens, "output_tokens": output_tokens},
        }

    return _build
