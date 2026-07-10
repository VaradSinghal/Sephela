"""
ai/llm/provider.py — Provider-agnostic LLM abstraction layer.

Agents NEVER call a provider directly. They call:

    response = await llm.generate(
        model_name="claude-3-5-sonnet-20241022",
        system_prompt="...",
        user_prompt="...",
        response_schema=MyPydanticModel,   # optional — triggers structured output
        temperature=0.1,
        max_tokens=8192,
    )

The LLMFactory selects and initialises the correct provider based on the model_name
by consulting the ModelRouter. Every provider implements BaseLLMProvider so the
call site never needs to branch on provider type.
"""

from __future__ import annotations

import abc
import json
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional, Type

from pydantic import BaseModel

_LOG = logging.getLogger("sephela.llm")


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class ProviderName(str, Enum):
    ANTHROPIC = "anthropic"
    OPENAI = "openai"
    OPENROUTER = "openrouter"
    GEMINI = "gemini"
    LOCAL = "local"


# ---------------------------------------------------------------------------
# Request / Response value objects
# ---------------------------------------------------------------------------


@dataclass
class ChatMessage:
    """A single message in a conversation."""

    role: str  # "system" | "user" | "assistant"
    content: str


@dataclass
class ChatCompletionRequest:
    """
    Provider-agnostic chat completion request.

    All fields are normalised before passing to the concrete provider adapter.
    """

    model: str
    messages: list[ChatMessage]
    temperature: float = 0.1
    max_tokens: int = 8192
    top_p: float = 1.0
    stop_sequences: list[str] = field(default_factory=list)
    response_format: Optional[str] = None   # "json_object" | "text"
    extra_params: dict[str, Any] = field(default_factory=dict)
    timeout_s: float = 120.0


@dataclass
class TokenUsage:
    """Token consumption details from the provider."""

    prompt_tokens: int = 0
    completion_tokens: int = 0

    @property
    def total_tokens(self) -> int:
        return self.prompt_tokens + self.completion_tokens


@dataclass
class ChatCompletionResponse:
    """
    Provider-agnostic chat completion response.

    Agents always receive this type — never a raw provider response object.
    """

    content: str
    model: str
    provider: ProviderName
    usage: TokenUsage
    latency_ms: int
    finish_reason: str  # "stop" | "max_tokens" | "error"
    raw: Any = None     # raw provider response for debugging


# ---------------------------------------------------------------------------
# Abstract provider
# ---------------------------------------------------------------------------


class BaseLLMProvider(abc.ABC):
    """
    Abstract base class every concrete LLM provider must implement.

    Contract
    --------
    * ``complete`` receives a normalised ``ChatCompletionRequest`` and returns a
      ``ChatCompletionResponse``.  It must NOT raise on API errors — instead it
      should propagate them so the caller (LLMGateway) can retry.
    * ``supports_model(model_id)`` returns True when this provider can serve
      the given model identifier.
    * ``provider_name`` is a read-only enum value identifying the adapter.
    """

    @property
    @abc.abstractmethod
    def provider_name(self) -> ProviderName:
        """Return the provider enum value for this adapter."""

    @abc.abstractmethod
    def supports_model(self, model_id: str) -> bool:
        """Return True if this provider can serve the given model identifier."""

    @abc.abstractmethod
    async def complete(self, request: ChatCompletionRequest) -> ChatCompletionResponse:
        """
        Execute a chat completion request.

        Args:
            request: Normalised ChatCompletionRequest.

        Returns:
            ChatCompletionResponse with normalised fields.

        Raises:
            Any exception from the underlying HTTP client; caller retries.
        """

    async def close(self) -> None:
        """Release underlying HTTP client resources (optional override)."""
