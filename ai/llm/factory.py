"""
ai/llm/factory.py — LLMFactory, ModelRouter, and the LLMGateway public interface.

The LLMGateway is the single entry point for all agent LLM calls:

    gateway = LLMGateway.from_env()           # reads env vars
    # or
    gateway = LLMGateway(providers=[...])     # explicit

    result = await gateway.generate(
        model_name="claude-3-5-sonnet-20241022",
        system_prompt="You are ...",
        user_prompt="Analyse this ...",
        response_schema=MyPydanticModel,      # optional
        temperature=0.1,
        max_tokens=8192,
    )
    # result.content  → raw string
    # result.parsed   → MyPydanticModel instance (if schema given)
    # result.usage    → TokenUsage

Retry and JSON-extraction are handled inside the gateway before returning to
the caller, so agents receive a clean, validated response.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import time
from dataclasses import dataclass, field
from typing import Any, Optional, Type

from pydantic import BaseModel

from ai.llm.provider import (
    BaseLLMProvider,
    ChatCompletionRequest,
    ChatCompletionResponse,
    ChatMessage,
    ProviderName,
    TokenUsage,
)

_LOG = logging.getLogger("sephela.llm.factory")


# ---------------------------------------------------------------------------
# Model → Provider routing table
# ---------------------------------------------------------------------------

# Map of model-id prefix → preferred ProviderName
# The ModelRouter walks this in order and returns the first matching adapter.
_MODEL_PROVIDER_MAP: dict[str, ProviderName] = {
    # Anthropic Claude family
    "claude": ProviderName.ANTHROPIC,
    # OpenAI GPT family
    "gpt-": ProviderName.OPENAI,
    "o1-": ProviderName.OPENAI,
    "o3-": ProviderName.OPENAI,
    # Google Gemini
    "gemini": ProviderName.GEMINI,
    # OpenRouter slug (contains slash)
    "/": ProviderName.OPENROUTER,
    # Local / self-hosted (explicit prefix)
    "local/": ProviderName.LOCAL,
    "ollama/": ProviderName.LOCAL,
}


class ModelRouter:
    """
    Routes a model identifier to the correct registered provider.

    Resolution order:
    1. Check if any registered provider explicitly supports the model.
    2. Fall back to prefix matching against ``_MODEL_PROVIDER_MAP``.
    3. If OpenRouter is registered, use it as a universal fallback.
    4. Raise ``LookupError`` if no provider can serve the model.
    """

    def __init__(self, providers: list[BaseLLMProvider]) -> None:
        self._by_name: dict[ProviderName, BaseLLMProvider] = {
            p.provider_name: p for p in providers
        }

    def resolve(self, model_id: str) -> BaseLLMProvider:
        # Step 1 — provider explicit support
        for provider in self._by_name.values():
            if provider.supports_model(model_id):
                return provider

        # Step 2 — prefix map
        for prefix, provider_name in _MODEL_PROVIDER_MAP.items():
            if model_id.startswith(prefix) or prefix in model_id:
                if provider_name in self._by_name:
                    return self._by_name[provider_name]

        # Step 3 — OpenRouter fallback
        if ProviderName.OPENROUTER in self._by_name:
            _LOG.warning("Using OpenRouter as fallback for unknown model %s", model_id)
            return self._by_name[ProviderName.OPENROUTER]

        raise LookupError(
            f"No registered provider can serve model '{model_id}'. "
            f"Registered: {list(self._by_name.keys())}"
        )


# ---------------------------------------------------------------------------
# LLMFactory — creates provider instances from config dicts
# ---------------------------------------------------------------------------


class LLMFactory:
    """
    Creates and caches ``BaseLLMProvider`` instances from configuration.

    Usage::

        factory = LLMFactory()
        factory.register_from_env()   # reads ANTHROPIC_API_KEY, OPENAI_API_KEY, etc.
        providers = factory.get_all()
    """

    def __init__(self) -> None:
        self._registry: dict[ProviderName, BaseLLMProvider] = {}

    def register(self, provider: BaseLLMProvider) -> "LLMFactory":
        """Register a pre-built provider adapter."""
        self._registry[provider.provider_name] = provider
        _LOG.info("Registered provider: %s", provider.provider_name.value)
        return self

    def register_from_env(self) -> "LLMFactory":
        """
        Auto-register providers by reading environment variables.

        Variables read:
        +-----------------------+------------------+
        | ANTHROPIC_API_KEY     | Anthropic         |
        | OPENAI_API_KEY        | OpenAI            |
        | OPENROUTER_API_KEY    | OpenRouter        |
        | GEMINI_API_KEY        | Gemini (compat)   |
        | LOCAL_LLM_BASE_URL    | Local/self-hosted |
        +-----------------------+------------------+
        """
        from ai.llm.adapters import (
            AnthropicAdapter,
            LocalAdapter,
            OpenAIAdapter,
            OpenRouterAdapter,
        )

        if key := os.getenv("ANTHROPIC_API_KEY"):
            self.register(AnthropicAdapter(api_key=key))

        if key := os.getenv("OPENAI_API_KEY"):
            self.register(OpenAIAdapter(api_key=key, provider=ProviderName.OPENAI))

        if key := os.getenv("OPENROUTER_API_KEY"):
            self.register(OpenRouterAdapter(api_key=key))

        if key := os.getenv("GEMINI_API_KEY"):
            from ai.llm.adapters import _GEMINI_BASE
            self.register(
                OpenAIAdapter(api_key=key, base_url=_GEMINI_BASE, provider=ProviderName.GEMINI)
            )

        if url := os.getenv("LOCAL_LLM_BASE_URL"):
            self.register(LocalAdapter(base_url=url))

        return self

    def get_all(self) -> list[BaseLLMProvider]:
        return list(self._registry.values())

    def get(self, name: ProviderName) -> Optional[BaseLLMProvider]:
        return self._registry.get(name)


# ---------------------------------------------------------------------------
# Generate result
# ---------------------------------------------------------------------------


@dataclass
class GenerateResult:
    """Result of a gateway.generate() call."""

    content: str                    # raw LLM text content
    parsed: Optional[Any]          # parsed Pydantic model instance (if schema given)
    model: str
    provider: ProviderName
    usage: TokenUsage
    latency_ms: int
    finish_reason: str
    attempts: int = 1


# ---------------------------------------------------------------------------
# LLMGateway — the only interface agents use
# ---------------------------------------------------------------------------

_JSON_FENCE_RE = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.DOTALL)


class LLMGateway:
    """
    Provider-agnostic LLM gateway.

    This is the **only** class agents import from ``ai.llm``.

    Features
    --------
    * Routes to the correct provider via ``ModelRouter``.
    * Adds JSON extraction from markdown code blocks.
    * Retries on transient errors with exponential back-off.
    * Validates output against a Pydantic schema when ``response_schema`` given.
    * Emits structured log lines for every call.
    """

    def __init__(
        self,
        providers: list[BaseLLMProvider],
        max_retries: int = 3,
        base_retry_delay_s: float = 2.0,
    ) -> None:
        self._router = ModelRouter(providers)
        self._max_retries = max_retries
        self._base_retry_delay = base_retry_delay_s

    # ------------------------------------------------------------------
    # Factory constructors
    # ------------------------------------------------------------------

    @classmethod
    def from_env(cls, max_retries: int = 3) -> "LLMGateway":
        """
        Construct a gateway by reading API keys from environment variables.

        Registers every provider whose API key is found in the environment.
        Raises ``RuntimeError`` if no providers can be registered.
        """
        factory = LLMFactory().register_from_env()
        providers = factory.get_all()
        if not providers:
            raise RuntimeError(
                "No LLM providers configured. Set at least one of: "
                "ANTHROPIC_API_KEY, OPENAI_API_KEY, OPENROUTER_API_KEY, "
                "GEMINI_API_KEY, LOCAL_LLM_BASE_URL"
            )
        return cls(providers=providers, max_retries=max_retries)

    @classmethod
    def from_providers(
        cls,
        providers: list[BaseLLMProvider],
        max_retries: int = 3,
    ) -> "LLMGateway":
        """Construct from a pre-built list of provider adapters."""
        return cls(providers=providers, max_retries=max_retries)

    # ------------------------------------------------------------------
    # Primary API
    # ------------------------------------------------------------------

    async def generate(
        self,
        model_name: str,
        system_prompt: str,
        user_prompt: str,
        response_schema: Optional[Type[BaseModel]] = None,
        temperature: float = 0.1,
        max_tokens: int = 8192,
        timeout_s: float = 120.0,
        extra_params: Optional[dict[str, Any]] = None,
    ) -> GenerateResult:
        """
        Generate a completion.

        Args:
            model_name:      LLM model identifier (e.g. "claude-3-5-sonnet-20241022").
            system_prompt:   System/context instructions.
            user_prompt:     User turn (evidence + analysis request).
            response_schema: Optional Pydantic model class.  When provided, the
                             gateway will extract JSON from the response and
                             validate it.  On schema mismatch, it retries with
                             an error-correction prompt.
            temperature:     Sampling temperature (0.0–1.0).
            max_tokens:      Maximum output tokens.
            timeout_s:       Per-attempt HTTP timeout in seconds.
            extra_params:    Additional provider-specific params.

        Returns:
            GenerateResult — always populated; ``parsed`` is None when no
            schema was requested or validation failed after all retries.
        """
        provider = self._router.resolve(model_name)

        # Force JSON mode when a schema is requested
        response_format = "json_object" if response_schema else None

        messages = [
            ChatMessage(role="system", content=system_prompt),
            ChatMessage(role="user", content=user_prompt),
        ]

        request = ChatCompletionRequest(
            model=model_name,
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
            response_format=response_format,
            timeout_s=timeout_s,
            extra_params=extra_params or {},
        )

        last_error: Optional[Exception] = None
        attempts = 0

        for attempt in range(self._max_retries):
            attempts = attempt + 1
            try:
                raw_response = await provider.complete(request)
                break
            except Exception as exc:  # noqa: BLE001
                last_error = exc
                delay = self._base_retry_delay * (2 ** attempt)
                _LOG.warning(
                    "LLM attempt %d/%d failed for model %s: %s — retrying in %.1fs",
                    attempt + 1, self._max_retries, model_name, exc, delay,
                )
                if attempt < self._max_retries - 1:
                    await asyncio.sleep(delay)
        else:
            # All retries exhausted
            raise RuntimeError(
                f"All {self._max_retries} LLM attempts failed for model {model_name}: {last_error}"
            ) from last_error

        _LOG.info(
            "LLM call succeeded: model=%s provider=%s tokens=%d latency_ms=%d",
            raw_response.model,
            raw_response.provider.value,
            raw_response.usage.total_tokens,
            raw_response.latency_ms,
        )

        # ------------------------------------------------------------------
        # Schema validation + retry with correction prompt
        # ------------------------------------------------------------------
        parsed: Optional[Any] = None
        if response_schema is not None:
            parsed, raw_response, attempts = await self._validate_with_retry(
                response_schema=response_schema,
                raw_response=raw_response,
                original_request=request,
                provider=provider,
                attempts=attempts,
            )

        return GenerateResult(
            content=raw_response.content,
            parsed=parsed,
            model=raw_response.model,
            provider=raw_response.provider,
            usage=raw_response.usage,
            latency_ms=raw_response.latency_ms,
            finish_reason=raw_response.finish_reason,
            attempts=attempts,
        )

    # ------------------------------------------------------------------
    # Internal: schema validation with self-correction
    # ------------------------------------------------------------------

    async def _validate_with_retry(
        self,
        response_schema: Type[BaseModel],
        raw_response: ChatCompletionResponse,
        original_request: ChatCompletionRequest,
        provider: BaseLLMProvider,
        attempts: int,
    ) -> tuple[Optional[Any], ChatCompletionResponse, int]:
        """
        Try to parse and validate the response against the schema.

        On failure, send a self-correction prompt and try once more.
        """
        # First pass — try to parse as-is
        parsed, error_msg = _try_parse(raw_response.content, response_schema)
        if parsed is not None:
            return parsed, raw_response, attempts

        # Self-correction: ask the model to fix its output
        _LOG.warning(
            "Schema validation failed (%s): %s — attempting self-correction",
            response_schema.__name__, error_msg,
        )

        schema_json = json.dumps(response_schema.model_json_schema(), indent=2)
        correction_prompt = (
            f"Your previous response could not be parsed as valid JSON matching the "
            f"required schema.\n\n"
            f"Error: {error_msg}\n\n"
            f"Required JSON schema:\n```json\n{schema_json}\n```\n\n"
            f"Previous response:\n{raw_response.content[:2000]}\n\n"
            f"Return ONLY valid JSON matching the schema above. No explanation. No markdown."
        )

        correction_messages = list(original_request.messages) + [
            ChatMessage(role="assistant", content=raw_response.content),
            ChatMessage(role="user", content=correction_prompt),
        ]

        correction_request = ChatCompletionRequest(
            model=original_request.model,
            messages=correction_messages,
            temperature=0.0,   # deterministic for correction
            max_tokens=original_request.max_tokens,
            response_format="json_object",
            timeout_s=original_request.timeout_s,
        )

        try:
            corrected_response = await provider.complete(correction_request)
            attempts += 1
            parsed, error_msg2 = _try_parse(corrected_response.content, response_schema)
            if parsed is not None:
                _LOG.info("Self-correction succeeded for %s", response_schema.__name__)
                return parsed, corrected_response, attempts
            _LOG.error(
                "Self-correction failed for %s: %s", response_schema.__name__, error_msg2
            )
            return None, corrected_response, attempts
        except Exception as exc:  # noqa: BLE001
            _LOG.error("Self-correction request failed: %s", exc)
            return None, raw_response, attempts

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def close(self) -> None:
        """Release all provider HTTP connections."""
        for provider in self._router._by_name.values():
            await provider.close()


# ---------------------------------------------------------------------------
# Internal parse helper
# ---------------------------------------------------------------------------


def _try_parse(
    content: str, schema: Type[BaseModel]
) -> tuple[Optional[BaseModel], Optional[str]]:
    """
    Attempt to extract JSON from content and validate against schema.

    Returns (parsed_model, None) on success or (None, error_message) on failure.
    """
    # 1. Try raw parse
    try:
        data = json.loads(content)
        return schema(**data), None
    except (json.JSONDecodeError, Exception):
        pass

    # 2. Try extracting from markdown fences
    match = _JSON_FENCE_RE.search(content)
    if match:
        try:
            data = json.loads(match.group(1))
            return schema(**data), None
        except Exception:
            pass

    # 3. Find the first { ... } block
    brace_start = content.find("{")
    brace_end = content.rfind("}")
    if brace_start != -1 and brace_end > brace_start:
        candidate = content[brace_start : brace_end + 1]
        try:
            data = json.loads(candidate)
            return schema(**data), None
        except json.JSONDecodeError as e:
            return None, f"JSON decode error: {e}"
        except Exception as e:
            return None, f"Schema validation error: {e}"

    return None, "No JSON object found in response"
