"""
ai/llm/adapters.py — Concrete provider adapters.

Each class wraps a single provider's HTTP API and implements BaseLLMProvider.
The LLMFactory instantiates and caches these; agents never touch them directly.

Providers implemented
---------------------
* AnthropicAdapter  — direct Anthropic Messages API
* OpenAIAdapter     — OpenAI Chat Completions API (also Gemini via compat endpoint)
* OpenRouterAdapter — OpenRouter unified gateway (covers 300+ models)
* LocalAdapter      — OpenAI-compatible local server (Ollama, LM Studio, vLLM)
"""

from __future__ import annotations

import json
import time
import logging
from typing import Any, Optional

import httpx

from ai.llm.provider import (
    BaseLLMProvider,
    ChatCompletionRequest,
    ChatCompletionResponse,
    ChatMessage,
    ProviderName,
    TokenUsage,
)

_LOG = logging.getLogger("sephela.llm.adapters")


# ---------------------------------------------------------------------------
# Helper: build HTTP client
# ---------------------------------------------------------------------------


def _build_client(base_url: str, headers: dict[str, str], timeout_s: float) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        base_url=base_url,
        headers=headers,
        timeout=httpx.Timeout(timeout_s, connect=10.0),
    )


# ---------------------------------------------------------------------------
# Anthropic adapter
# ---------------------------------------------------------------------------

_ANTHROPIC_BASE = "https://api.anthropic.com"
_ANTHROPIC_VERSION = "2023-06-01"
_ANTHROPIC_PREFIX = "claude"


class AnthropicAdapter(BaseLLMProvider):
    """Direct Anthropic Messages API adapter."""

    def __init__(self, api_key: str, base_url: str = _ANTHROPIC_BASE) -> None:
        self._api_key = api_key
        self._base_url = base_url
        self._client: Optional[httpx.AsyncClient] = None

    @property
    def provider_name(self) -> ProviderName:
        return ProviderName.ANTHROPIC

    def supports_model(self, model_id: str) -> bool:
        return model_id.startswith(_ANTHROPIC_PREFIX)

    def _get_client(self, timeout_s: float) -> httpx.AsyncClient:
        if self._client is None:
            self._client = _build_client(
                self._base_url,
                {
                    "x-api-key": self._api_key,
                    "anthropic-version": _ANTHROPIC_VERSION,
                    "content-type": "application/json",
                    "anthropic-beta": "messages-2023-12-15",
                },
                timeout_s,
            )
        return self._client

    async def complete(self, request: ChatCompletionRequest) -> ChatCompletionResponse:
        client = self._get_client(request.timeout_s)

        # Separate system message from user messages
        system_content = ""
        user_messages = []
        for msg in request.messages:
            if msg.role == "system":
                system_content = msg.content
            else:
                user_messages.append({"role": msg.role, "content": msg.content})

        if not user_messages:
            user_messages = [{"role": "user", "content": "Proceed."}]

        payload: dict[str, Any] = {
            "model": request.model,
            "messages": user_messages,
            "temperature": request.temperature,
            "max_tokens": request.max_tokens,
        }
        if system_content:
            payload["system"] = system_content
        if request.stop_sequences:
            payload["stop_sequences"] = request.stop_sequences

        t0 = time.perf_counter()
        resp = await client.post("/v1/messages", json=payload)
        resp.raise_for_status()
        latency_ms = int((time.perf_counter() - t0) * 1000)

        data = resp.json()
        content = "".join(
            block["text"] for block in data.get("content", []) if block.get("type") == "text"
        )
        usage_data = data.get("usage", {})

        return ChatCompletionResponse(
            content=content,
            model=data.get("model", request.model),
            provider=ProviderName.ANTHROPIC,
            usage=TokenUsage(
                prompt_tokens=usage_data.get("input_tokens", 0),
                completion_tokens=usage_data.get("output_tokens", 0),
            ),
            latency_ms=latency_ms,
            finish_reason=data.get("stop_reason", "end_turn"),
            raw=data,
        )

    async def close(self) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None


# ---------------------------------------------------------------------------
# OpenAI adapter (also handles Gemini via compat endpoint)
# ---------------------------------------------------------------------------

_OPENAI_BASE = "https://api.openai.com/v1"
_GEMINI_BASE = "https://generativelanguage.googleapis.com/v1beta/openai"


class OpenAIAdapter(BaseLLMProvider):
    """
    OpenAI Chat Completions API adapter.

    Set ``base_url`` to ``_GEMINI_BASE`` for Gemini models via the
    OpenAI-compatible endpoint (Gemini 1.5+ supports this).
    """

    def __init__(
        self,
        api_key: str,
        base_url: str = _OPENAI_BASE,
        provider: ProviderName = ProviderName.OPENAI,
    ) -> None:
        self._api_key = api_key
        self._base_url = base_url
        self._provider = provider
        self._client: Optional[httpx.AsyncClient] = None

    @property
    def provider_name(self) -> ProviderName:
        return self._provider

    def supports_model(self, model_id: str) -> bool:
        if self._provider == ProviderName.OPENAI:
            return model_id.startswith(("gpt-", "o1-", "o3-", "text-"))
        if self._provider == ProviderName.GEMINI:
            return model_id.startswith("gemini")
        return False

    def _get_client(self, timeout_s: float) -> httpx.AsyncClient:
        if self._client is None:
            self._client = _build_client(
                self._base_url,
                {
                    "Authorization": f"Bearer {self._api_key}",
                    "Content-Type": "application/json",
                },
                timeout_s,
            )
        return self._client

    async def complete(self, request: ChatCompletionRequest) -> ChatCompletionResponse:
        client = self._get_client(request.timeout_s)

        messages = [{"role": m.role, "content": m.content} for m in request.messages]

        payload: dict[str, Any] = {
            "model": request.model,
            "messages": messages,
            "temperature": request.temperature,
            "max_tokens": request.max_tokens,
        }
        if request.response_format == "json_object":
            payload["response_format"] = {"type": "json_object"}
        if request.stop_sequences:
            payload["stop"] = request.stop_sequences

        t0 = time.perf_counter()
        resp = await client.post("/chat/completions", json=payload)
        resp.raise_for_status()
        latency_ms = int((time.perf_counter() - t0) * 1000)

        data = resp.json()
        choice = data["choices"][0]
        usage_data = data.get("usage", {})

        return ChatCompletionResponse(
            content=choice["message"]["content"] or "",
            model=data.get("model", request.model),
            provider=self._provider,
            usage=TokenUsage(
                prompt_tokens=usage_data.get("prompt_tokens", 0),
                completion_tokens=usage_data.get("completion_tokens", 0),
            ),
            latency_ms=latency_ms,
            finish_reason=choice.get("finish_reason", "stop"),
            raw=data,
        )

    async def close(self) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None


# ---------------------------------------------------------------------------
# OpenRouter adapter
# ---------------------------------------------------------------------------

_OPENROUTER_BASE = "https://openrouter.ai/api/v1"


class OpenRouterAdapter(BaseLLMProvider):
    """
    OpenRouter unified gateway — supports 300+ models from all major providers.

    Model IDs use the ``provider/model`` slug format, e.g.:
      ``anthropic/claude-3.5-sonnet``
      ``openai/gpt-4o``
      ``google/gemini-pro-1.5``
      ``meta-llama/llama-3.1-70b-instruct``
    """

    def __init__(
        self,
        api_key: str,
        site_url: str = "https://sephela.io",
        site_name: str = "Sephela APK Analysis",
    ) -> None:
        self._api_key = api_key
        self._site_url = site_url
        self._site_name = site_name
        self._client: Optional[httpx.AsyncClient] = None

    @property
    def provider_name(self) -> ProviderName:
        return ProviderName.OPENROUTER

    def supports_model(self, model_id: str) -> bool:
        # OpenRouter models are provider-prefixed OR match well-known patterns
        return "/" in model_id or model_id in _OPENROUTER_KNOWN_BARE

    def _get_client(self, timeout_s: float) -> httpx.AsyncClient:
        if self._client is None:
            self._client = _build_client(
                _OPENROUTER_BASE,
                {
                    "Authorization": f"Bearer {self._api_key}",
                    "Content-Type": "application/json",
                    "HTTP-Referer": self._site_url,
                    "X-Title": self._site_name,
                },
                timeout_s,
            )
        return self._client

    async def complete(self, request: ChatCompletionRequest) -> ChatCompletionResponse:
        client = self._get_client(request.timeout_s)

        messages = [{"role": m.role, "content": m.content} for m in request.messages]

        payload: dict[str, Any] = {
            "model": request.model,
            "messages": messages,
            "temperature": request.temperature,
            "max_tokens": request.max_tokens,
        }
        if request.response_format == "json_object":
            payload["response_format"] = {"type": "json_object"}
        payload.update(request.extra_params)

        t0 = time.perf_counter()
        resp = await client.post("/chat/completions", json=payload)
        resp.raise_for_status()
        latency_ms = int((time.perf_counter() - t0) * 1000)

        data = resp.json()
        choice = data["choices"][0]
        usage_data = data.get("usage", {})

        return ChatCompletionResponse(
            content=choice["message"]["content"] or "",
            model=data.get("model", request.model),
            provider=ProviderName.OPENROUTER,
            usage=TokenUsage(
                prompt_tokens=usage_data.get("prompt_tokens", 0),
                completion_tokens=usage_data.get("completion_tokens", 0),
            ),
            latency_ms=latency_ms,
            finish_reason=choice.get("finish_reason", "stop"),
            raw=data,
        )

    async def close(self) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None


# Bare model names OpenRouter also accepts (without provider prefix)
_OPENROUTER_KNOWN_BARE: frozenset[str] = frozenset()


# ---------------------------------------------------------------------------
# Local adapter (Ollama / LM Studio / vLLM — OpenAI-compatible)
# ---------------------------------------------------------------------------


class LocalAdapter(BaseLLMProvider):
    """
    Adapter for self-hosted OpenAI-compatible servers.

    Examples:
        LocalAdapter(base_url="http://localhost:11434/v1")  # Ollama
        LocalAdapter(base_url="http://localhost:1234/v1")   # LM Studio
    """

    def __init__(self, base_url: str, api_key: str = "local") -> None:
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._client: Optional[httpx.AsyncClient] = None

    @property
    def provider_name(self) -> ProviderName:
        return ProviderName.LOCAL

    def supports_model(self, model_id: str) -> bool:
        # Accept anything — the local server decides
        return True

    def _get_client(self, timeout_s: float) -> httpx.AsyncClient:
        if self._client is None:
            self._client = _build_client(
                self._base_url,
                {
                    "Authorization": f"Bearer {self._api_key}",
                    "Content-Type": "application/json",
                },
                timeout_s,
            )
        return self._client

    async def complete(self, request: ChatCompletionRequest) -> ChatCompletionResponse:
        client = self._get_client(request.timeout_s)

        messages = [{"role": m.role, "content": m.content} for m in request.messages]

        payload: dict[str, Any] = {
            "model": request.model,
            "messages": messages,
            "temperature": request.temperature,
            "max_tokens": request.max_tokens,
        }

        t0 = time.perf_counter()
        resp = await client.post("/chat/completions", json=payload)
        resp.raise_for_status()
        latency_ms = int((time.perf_counter() - t0) * 1000)

        data = resp.json()
        choice = data["choices"][0]
        usage_data = data.get("usage", {})

        return ChatCompletionResponse(
            content=choice["message"]["content"] or "",
            model=data.get("model", request.model),
            provider=ProviderName.LOCAL,
            usage=TokenUsage(
                prompt_tokens=usage_data.get("prompt_tokens", 0),
                completion_tokens=usage_data.get("completion_tokens", 0),
            ),
            latency_ms=latency_ms,
            finish_reason=choice.get("finish_reason", "stop"),
            raw=data,
        )

    async def close(self) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None
