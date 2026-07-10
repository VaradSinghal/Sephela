"""
ai/llm/__init__.py — Public surface of the LLM abstraction layer.

Agents import only:
    from ai.llm import LLMGateway, GenerateResult

Everything else (adapters, factory, model registry) is implementation detail.
"""

from ai.llm.provider import (
    BaseLLMProvider,
    ChatCompletionRequest,
    ChatCompletionResponse,
    ChatMessage,
    ProviderName,
    TokenUsage,
)
from ai.llm.adapters import (
    AnthropicAdapter,
    LocalAdapter,
    OpenAIAdapter,
    OpenRouterAdapter,
)
from ai.llm.factory import (
    GenerateResult,
    LLMFactory,
    LLMGateway,
    ModelRouter,
)
from ai.llm.models import (
    MODEL_REGISTRY,
    ModelInfo,
    ModelProvider,
    TASK_MODEL_MAP,
    estimate_cost,
    get_model_info,
    get_recommended_model,
    list_models,
)
from ai.llm.client import LLMClient, LLMConfig, LLMResponse
from ai.llm.streaming import StreamingHandler

__all__ = [
    # Core gateway — what agents use
    "LLMGateway",
    "GenerateResult",
    # Provider abstractions
    "BaseLLMProvider",
    "ProviderName",
    "ChatCompletionRequest",
    "ChatCompletionResponse",
    "ChatMessage",
    "TokenUsage",
    # Concrete adapters
    "AnthropicAdapter",
    "OpenAIAdapter",
    "OpenRouterAdapter",
    "LocalAdapter",
    # Factory utilities
    "LLMFactory",
    "ModelRouter",
    # Model registry
    "MODEL_REGISTRY",
    "ModelInfo",
    "ModelProvider",
    "TASK_MODEL_MAP",
    "get_model_info",
    "get_recommended_model",
    "list_models",
    "estimate_cost",
    # Legacy compat
    "LLMClient",
    "LLMConfig",
    "LLMResponse",
    "StreamingHandler",
]