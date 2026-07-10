"""Base LLM client interface and configuration."""

from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, AsyncIterator, Dict, List, Optional
from enum import Enum


class ModelProvider(str, Enum):
    """Supported model providers."""
    ANTHROPIC = "anthropic"
    OPENAI = "openai"
    OPENROUTER = "openrouter"
    LOCAL = "local"


@dataclass
class LLMConfig:
    """Configuration for LLM client."""
    provider: ModelProvider
    model: str
    api_key: str
    base_url: Optional[str] = None
    temperature: float = 0.1
    max_tokens: int = 8192
    timeout_seconds: int = 120
    max_retries: int = 3
    retry_delay: float = 1.0
    extra_params: Dict[str, Any] = field(default_factory=dict)


@dataclass
class LLMResponse:
    """Standardized LLM response."""
    content: str
    model: str
    provider: ModelProvider
    tokens_used: int
    latency_ms: int
    finish_reason: str
    raw_response: Any = None


@dataclass
class StreamingChunk:
    """Single chunk in streaming response."""
    content: str
    is_final: bool
    tokens_so_far: int


class LLMClient(ABC):
    """Abstract base class for LLM clients."""

    def __init__(self, config: LLMConfig):
        self.config = config
        self._client = None
    
    @abstractmethod
    async def initialize(self) -> None:
        """Initialize the client connection."""
        pass
    
    @abstractmethod
    async def complete(self, prompt: str, **kwargs) -> LLMResponse:
        """Generate a completion for the given prompt."""
        pass
    
    @abstractmethod
    async def stream_complete(self, prompt: str, **kwargs) -> AsyncIterator[StreamingChunk]:
        """Stream a completion for the given prompt."""
        pass
    
    @abstractmethod
    async def close(self) -> None:
        """Close the client connection."""
        pass


class BaseAsyncClient(LLMClient):
    """Base implementation with common retry logic."""

    async def _retry_with_backoff(self, func, *args, **kwargs):
        """Execute function with exponential backoff retry."""
        last_exception = None
        
        for attempt in range(self.config.max_retries + 1):
            try:
                return await func(*args, **kwargs)
            except Exception as e:
                last_exception = e
                if attempt < self.config.max_retries:
                    delay = self.config.retry_delay * (2 ** attempt)
                    await asyncio.sleep(delay)
                else:
                    break
        
        raise last_exception

    def _estimate_tokens(self, text: str) -> int:
        """Rough token estimation (4 chars ≈ 1 token)."""
        return len(text) // 4