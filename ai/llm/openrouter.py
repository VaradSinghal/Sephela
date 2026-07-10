"""OpenRouter API client for accessing multiple LLM providers."""

from __future__ import annotations

import asyncio
import json
import time
from typing import Any, AsyncIterator, Dict, List, Optional

import httpx

from ai.llm.client import LLMClient, LLMConfig, LLMResponse, StreamingChunk, ModelProvider


class OpenRouterClient(LLMClient):
    """OpenRouter API client with unified interface for multiple models."""

    def __init__(self, config: LLMConfig):
        super().__init__(config)
        self.config.provider = ModelProvider.OPENROUTER
        self.base_url = config.base_url or "https://openrouter.ai/api/v1"
        self._client: Optional[httpx.AsyncClient] = None

    async def initialize(self) -> None:
        """Initialize HTTP client."""
        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            headers={
                "Authorization": f"Bearer {self.config.api_key}",
                "Content-Type": "application/json",
                "HTTP-Referer": "https://sephela.io",
                "X-Title": "Sephela Malware Analysis",
            },
            timeout=httpx.Timeout(self.config.timeout_seconds),
        )

    async def complete(self, prompt: str, **kwargs) -> LLMResponse:
        """Generate completion via OpenRouter."""
        if not self._client:
            await self.initialize()

        payload = {
            "model": self.config.model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": kwargs.get("temperature", self.config.temperature),
            "max_tokens": kwargs.get("max_tokens", self.config.max_tokens),
            "stream": False,
            **self.config.extra_params,
        }

        start_time = time.time()
        
        async def _request():
            response = await self._client.post("/chat/completions", json=payload)
            response.raise_for_status()
            return response.json()

        data = await self._retry_with_backoff(_request)
        latency_ms = int((time.time() - start_time) * 1000)

        choice = data["choices"][0]
        content = choice["message"]["content"]
        tokens = data.get("usage", {}).get("total_tokens", self._estimate_tokens(content))

        return LLMResponse(
            content=content,
            model=data.get("model", self.config.model),
            provider=ModelProvider.OPENROUTER,
            tokens_used=tokens,
            latency_ms=latency_ms,
            finish_reason=choice.get("finish_reason", "stop"),
            raw_response=data,
        )

    async def stream_complete(self, prompt: str, **kwargs) -> AsyncIterator[StreamingChunk]:
        """Stream completion via OpenRouter."""
        if not self._client:
            await self.initialize()

        payload = {
            "model": self.config.model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": kwargs.get("temperature", self.config.temperature),
            "max_tokens": kwargs.get("max_tokens", self.config.max_tokens),
            "stream": True,
            **self.config.extra_params,
        }

        async with self._client.stream("POST", "/chat/completions", json=payload) as response:
            response.raise_for_status()
            tokens = 0
            
            async for line in response.aiter_lines():
                if line.startswith("data: "):
                    data_str = line[6:]
                    if data_str.strip() == "[DONE]":
                        break
                    try:
                        data = json.loads(data_str)
                        delta = data["choices"][0]["delta"]
                        content = delta.get("content", "")
                        finish_reason = data["choices"][0].get("finish_reason")
                        
                        if content:
                            tokens += len(content) // 4
                            yield StreamingChunk(
                                content=content,
                                is_final=finish_reason is not None,
                                tokens_so_far=tokens,
                            )
                    except json.JSONDecodeError:
                        continue

    async def close(self) -> None:
        """Close HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None


class OpenRouterModelRegistry:
    """Registry of available models on OpenRouter."""

    RECOMMENDED_MODELS = {
        "analysis": [
            "anthropic/claude-3.5-sonnet",
            "anthropic/claude-3.5-haiku",
            "anthropic/claude-3-opus",
            "openai/gpt-4o",
            "openai/gpt-4o-mini",
        ],
        "fast": [
            "anthropic/claude-3.5-haiku",
            "openai/gpt-4o-mini",
            "google/gemini-flash-1.5",
        ],
        "cost_effective": [
            "meta-llama/llama-3.1-8b-instruct",
            "mistralai/mistral-7b-instruct",
            "google/gemma-2-9b-it",
        ],
        "specialized_code": [
            "anthropic/claude-3.5-sonnet",
            "openai/gpt-4o",
            "deepseek/deepseek-coder",
        ],
    }

    @classmethod
    def get_model_for_task(cls, task: str) -> str:
        """Get recommended model for a specific task."""
        models = cls.RECOMMENDED_MODELS.get(task, cls.RECOMMENDED_MODELS["analysis"])
        return models[0]

    @classmethod
    async def fetch_available_models(cls, api_key: str) -> List[Dict[str, Any]]:
        """Fetch currently available models from OpenRouter API."""
        async with httpx.AsyncClient() as client:
            response = await client.get(
                "https://openrouter.ai/api/v1/models",
                headers={"Authorization": f"Bearer {api_key}"},
            )
            response.raise_for_status()
            return response.json().get("data", [])