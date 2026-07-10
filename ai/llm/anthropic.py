"""Anthropic API client for direct Claude access."""

from __future__ import annotations

import time
from typing import Any, AsyncIterator, Dict, List, Optional

import httpx

from ai.llm.client import LLMClient, LLMConfig, LLMResponse, StreamingChunk, ModelProvider


class AnthropicClient(LLMClient):
    """Anthropic API client for direct Claude access."""

    def __init__(self, config: LLMConfig):
        super().__init__(config)
        self.config.provider = ModelProvider.ANTHROPIC
        self.base_url = config.base_url or "https://api.anthropic.com"
        self._client: Optional[httpx.AsyncClient] = None
        self.api_version = "2023-06-01"
        self.beta_headers = ["messages-2023-12-15"]

    async def initialize(self) -> None:
        """Initialize HTTP client."""
        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            headers={
                "x-api-key": self.config.api_key,
                "Content-Type": "application/json",
                "anthropic-version": self.api_version,
                "anthropic-beta": ",".join(self.beta_headers),
            },
            timeout=httpx.Timeout(self.config.timeout_seconds),
        )

    async def complete(self, prompt: str, **kwargs) -> LLMResponse:
        """Generate completion via Anthropic."""
        if not self._client:
            await self.initialize()

        system_prompt = kwargs.get("system_prompt", "")
        messages = [{"role": "user", "content": prompt}]

        payload = {
            "model": self.config.model,
            "messages": messages,
            "temperature": kwargs.get("temperature", self.config.temperature),
            "max_tokens": kwargs.get("max_tokens", self.config.max_tokens),
            "stream": False,
        }

        if system_prompt:
            payload["system"] = system_prompt

        start_time = time.time()

        async def _request():
            response = await self._client.post("/v1/messages", json=payload)
            response.raise_for_status()
            return response.json()

        data = await self._retry_with_backoff(_request)
        latency_ms = int((time.time() - start_time) * 1000)

        content = "".join(block["text"] for block in data["content"] if block["type"] == "text")
        tokens = data.get("usage", {}).get("input_tokens", 0) + data.get("usage", {}).get("output_tokens", 0)

        return LLMResponse(
            content=content,
            model=data.get("model", self.config.model),
            provider=ModelProvider.ANTHROPIC,
            tokens_used=tokens,
            latency_ms=latency_ms,
            finish_reason=data.get("stop_reason", "end_turn"),
            raw_response=data,
        )

    async def stream_complete(self, prompt: str, **kwargs) -> AsyncIterator[StreamingChunk]:
        """Stream completion via Anthropic."""
        if not self._client:
            await self.initialize()

        system_prompt = kwargs.get("system_prompt", "")
        messages = [{"role": "user", "content": prompt}]

        payload = {
            "model": self.config.model,
            "messages": messages,
            "temperature": kwargs.get("temperature", self.config.temperature),
            "max_tokens": kwargs.get("max_tokens", self.config.max_tokens),
            "stream": True,
        }

        if system_prompt:
            payload["system"] = system_prompt

        async with self._client.stream("POST", "/v1/messages", json=payload) as response:
            response.raise_for_status()
            tokens = 0

            async for line in response.aiter_lines():
                if line.startswith("data: "):
                    data_str = line[6:]
                    if data_str.strip() == "[DONE]":
                        break
                    try:
                        import json
                        data = json.loads(data_str)
                        if data["type"] == "content_block_delta":
                            delta = data["delta"]
                            if delta["type"] == "text_delta":
                                content = delta["text"]
                                tokens += len(content) // 4
                                yield StreamingChunk(
                                    content=content,
                                    is_final=False,
                                    tokens_so_far=tokens,
                                )
                        elif data["type"] == "message_stop":
                            yield StreamingChunk(content="", is_final=True, tokens_so_far=tokens)
                    except json.JSONDecodeError:
                        continue

    async def close(self) -> None:
        """Close HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None