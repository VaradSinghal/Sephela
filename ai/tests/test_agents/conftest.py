"""Shared doubles for the agent suites.

The gateway double lives here rather than in each test file because the whole point
of these tests is that every agent talks to the *same* client interface. Eight
private copies of it would let one agent drift without anything noticing.
"""

from __future__ import annotations

import json
from typing import Any

import pytest


class _Usage:
    def __init__(self, total: int) -> None:
        self.total_tokens = total


class _GenerateResult:
    def __init__(self, content: str, tokens: int) -> None:
        self.content = content
        self.usage = _Usage(tokens)


class FakeGateway:
    """``LLMGateway``-shaped: routes on ``generate(**kwargs)``.

    Records every call so a test can assert on what the agent asked for, which is
    the half of the contract that a returned value cannot show.
    """

    def __init__(self, response: Any = None, tokens: int = 512) -> None:
        if response is None:
            response = {}
        self._content = response if isinstance(response, str) else json.dumps(response)
        self._tokens = tokens
        self.calls: list[dict[str, Any]] = []

    async def generate(self, **kwargs: Any) -> _GenerateResult:
        self.calls.append(kwargs)
        return _GenerateResult(self._content, self._tokens)

    @property
    def last_user_prompt(self) -> str:
        return str(self.calls[-1]["user_prompt"])


@pytest.fixture
def gateway_for():
    """Build a ``FakeGateway`` that answers with ``payload``."""

    def _build(payload: Any = None, tokens: int = 512) -> FakeGateway:
        return FakeGateway(payload, tokens=tokens)

    return _build
