"""Model registry and cost estimation for LLM models."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class ModelProvider(str, Enum):
    """Supported LLM providers."""

    ANTHROPIC = "anthropic"
    OPENAI = "openai"
    OPENROUTER = "openrouter"
    LOCAL = "local"


class ModelCapability(str, Enum):
    """Model capabilities."""

    TEXT = "text"
    VISION = "vision"
    FUNCTION_CALLING = "function_calling"
    STRUCTURED_OUTPUT = "structured_output"
    STREAMING = "streaming"
    LONG_CONTEXT = "long_context"
    REASONING = "reasoning"


@dataclass
class ModelInfo:
    """Information about a specific model."""

    id: str
    name: str
    provider: ModelProvider
    capabilities: list[ModelCapability] = field(default_factory=list)
    context_window: int = 4096
    max_output_tokens: int = 4096
    cost_per_1k_input: float = 0.0
    cost_per_1k_output: float = 0.0
    description: str = ""
    deprecated: bool = False


# Predefined model registry
MODEL_REGISTRY: dict[str, ModelInfo] = {
    # Anthropic
    # Output ceilings are the streaming maxima — anything over ~16k output must
    # be streamed or the SDK's HTTP timeout fires before the response completes.
    "nvidia/nemotron-3-super-120b-a12b:free": ModelInfo(
        id="nvidia/nemotron-3-super-120b-a12b:free",
        name="Claude Opus 5",
        provider=ModelProvider.ANTHROPIC,
        capabilities=[
            ModelCapability.TEXT,
            ModelCapability.VISION,
            ModelCapability.FUNCTION_CALLING,
            ModelCapability.STRUCTURED_OUTPUT,
            ModelCapability.STREAMING,
            ModelCapability.LONG_CONTEXT,
            ModelCapability.REASONING,
        ],
        context_window=1_000_000,
        max_output_tokens=128000,
        cost_per_1k_input=0.005,
        cost_per_1k_output=0.025,
        description="Default for every agent — strongest reasoning over evidence",
    ),
    "claude-sonnet-5": ModelInfo(
        id="claude-sonnet-5",
        name="Claude Sonnet 5",
        provider=ModelProvider.ANTHROPIC,
        capabilities=[
            ModelCapability.TEXT,
            ModelCapability.VISION,
            ModelCapability.FUNCTION_CALLING,
            ModelCapability.STRUCTURED_OUTPUT,
            ModelCapability.STREAMING,
            ModelCapability.LONG_CONTEXT,
            ModelCapability.REASONING,
        ],
        context_window=1_000_000,
        max_output_tokens=128000,
        cost_per_1k_input=0.003,
        cost_per_1k_output=0.015,
        description="Cost/quality middle ground for high-volume analysis",
    ),
    "claude-haiku-4-5": ModelInfo(
        id="claude-haiku-4-5",
        name="Claude Haiku 4.5",
        provider=ModelProvider.ANTHROPIC,
        capabilities=[
            ModelCapability.TEXT,
            ModelCapability.FUNCTION_CALLING,
            ModelCapability.STRUCTURED_OUTPUT,
            ModelCapability.STREAMING,
            ModelCapability.LONG_CONTEXT,
        ],
        context_window=200000,
        max_output_tokens=64000,
        cost_per_1k_input=0.001,
        cost_per_1k_output=0.005,
        description="Fast, cheap model for triage and high-volume classification",
    ),
    # OpenAI
    "gpt-4o": ModelInfo(
        id="gpt-4o",
        name="GPT-4o",
        provider=ModelProvider.OPENAI,
        capabilities=[
            ModelCapability.TEXT,
            ModelCapability.VISION,
            ModelCapability.FUNCTION_CALLING,
            ModelCapability.STRUCTURED_OUTPUT,
            ModelCapability.STREAMING,
            ModelCapability.LONG_CONTEXT,
            ModelCapability.REASONING,
        ],
        context_window=128000,
        max_output_tokens=16384,
        cost_per_1k_input=0.005,
        cost_per_1k_output=0.015,
        description="OpenAI's flagship multimodal model",
    ),
    "gpt-4o-mini": ModelInfo(
        id="gpt-4o-mini",
        name="GPT-4o Mini",
        provider=ModelProvider.OPENAI,
        capabilities=[
            ModelCapability.TEXT,
            ModelCapability.VISION,
            ModelCapability.FUNCTION_CALLING,
            ModelCapability.STRUCTURED_OUTPUT,
            ModelCapability.STREAMING,
            ModelCapability.LONG_CONTEXT,
        ],
        context_window=128000,
        max_output_tokens=16384,
        cost_per_1k_input=0.00015,
        cost_per_1k_output=0.0006,
        description="Cost-effective small model",
    ),
    # OpenRouter (models accessed via OpenRouter)
    # OpenRouter prefixes the upstream id with the vendor slug. Its catalogue lags
    # first-party releases, so confirm the slug at
    # https://openrouter.ai/models before pointing a deployment at it.
    "anthropic/nvidia/nemotron-3-super-120b-a12b:free": ModelInfo(
        id="anthropic/nvidia/nemotron-3-super-120b-a12b:free",
        name="Claude Opus 5 (OpenRouter)",
        provider=ModelProvider.OPENROUTER,
        capabilities=[
            ModelCapability.TEXT,
            ModelCapability.VISION,
            ModelCapability.FUNCTION_CALLING,
            ModelCapability.STRUCTURED_OUTPUT,
            ModelCapability.STREAMING,
            ModelCapability.LONG_CONTEXT,
            ModelCapability.REASONING,
        ],
        context_window=1_000_000,
        max_output_tokens=128000,
        cost_per_1k_input=0.005,
        cost_per_1k_output=0.025,
        description="Claude Opus 5 via OpenRouter",
    ),
    "openai/gpt-4o": ModelInfo(
        id="openai/gpt-4o",
        name="GPT-4o (OpenRouter)",
        provider=ModelProvider.OPENROUTER,
        capabilities=[
            ModelCapability.TEXT,
            ModelCapability.VISION,
            ModelCapability.FUNCTION_CALLING,
            ModelCapability.STRUCTURED_OUTPUT,
            ModelCapability.STREAMING,
            ModelCapability.LONG_CONTEXT,
            ModelCapability.REASONING,
        ],
        context_window=128000,
        max_output_tokens=16384,
        cost_per_1k_input=0.005,
        cost_per_1k_output=0.015,
        description="GPT-4o via OpenRouter",
    ),
    "deepseek/deepseek-coder": ModelInfo(
        id="deepseek/deepseek-coder",
        name="DeepSeek Coder",
        provider=ModelProvider.OPENROUTER,
        capabilities=[
            ModelCapability.TEXT,
            ModelCapability.FUNCTION_CALLING,
            ModelCapability.STRUCTURED_OUTPUT,
            ModelCapability.STREAMING,
            ModelCapability.LONG_CONTEXT,
        ],
        context_window=64000,
        max_output_tokens=8192,
        cost_per_1k_input=0.00014,
        cost_per_1k_output=0.00028,
        description="Specialized for code analysis tasks",
    ),
    "meta-llama/llama-3.1-70b-instruct": ModelInfo(
        id="meta-llama/llama-3.1-70b-instruct",
        name="Llama 3.1 70B Instruct",
        provider=ModelProvider.OPENROUTER,
        capabilities=[
            ModelCapability.TEXT,
            ModelCapability.FUNCTION_CALLING,
            ModelCapability.STRUCTURED_OUTPUT,
            ModelCapability.STREAMING,
            ModelCapability.LONG_CONTEXT,
        ],
        context_window=131072,
        max_output_tokens=8192,
        cost_per_1k_input=0.0009,
        cost_per_1k_output=0.0009,
        description="Open-weight model, good balance of cost/performance",
    ),
}


# Task-specific model recommendations
TASK_MODEL_MAP = {
    "manifest_analysis": ["nvidia/nemotron-3-super-120b-a12b:free", "anthropic/nvidia/nemotron-3-super-120b-a12b:free", "gpt-4o"],
    "permission_analysis": ["nvidia/nemotron-3-super-120b-a12b:free", "anthropic/nvidia/nemotron-3-super-120b-a12b:free", "gpt-4o"],
    "code_analysis": ["nvidia/nemotron-3-super-120b-a12b:free", "deepseek/deepseek-coder", "gpt-4o"],
    "api_analysis": ["nvidia/nemotron-3-super-120b-a12b:free", "deepseek/deepseek-coder", "gpt-4o"],
    "network_analysis": ["nvidia/nemotron-3-super-120b-a12b:free", "anthropic/nvidia/nemotron-3-super-120b-a12b:free", "gpt-4o"],
    "threat_intel": ["nvidia/nemotron-3-super-120b-a12b:free", "anthropic/nvidia/nemotron-3-super-120b-a12b:free", "gpt-4o"],
    "risk_scoring": ["nvidia/nemotron-3-super-120b-a12b:free", "anthropic/nvidia/nemotron-3-super-120b-a12b:free", "gpt-4o"],
    "report_generation": ["nvidia/nemotron-3-super-120b-a12b:free", "anthropic/nvidia/nemotron-3-super-120b-a12b:free", "gpt-4o"],
    "fast_classification": ["claude-haiku-4-5", "gpt-4o-mini", "meta-llama/llama-3.1-70b-instruct"],
}


def get_model_info(model_id: str) -> ModelInfo | None:
    """Get model info by ID."""
    return MODEL_REGISTRY.get(model_id)


def get_recommended_model(task: str, provider: ModelProvider | None = None) -> str:
    """Get recommended model for a task."""
    models = TASK_MODEL_MAP.get(task, TASK_MODEL_MAP["manifest_analysis"])

    if provider:
        for model_id in models:
            if MODEL_REGISTRY[model_id].provider == provider:
                return model_id

    return models[0]


def list_models(
    provider: ModelProvider | None = None,
    capability: ModelCapability | None = None,
) -> list[ModelInfo]:
    """List models with optional filters."""
    models = list(MODEL_REGISTRY.values())

    if provider:
        models = [m for m in models if m.provider == provider]

    if capability:
        models = [m for m in models if capability in m.capabilities]

    return sorted(models, key=lambda m: m.cost_per_1k_input)


def estimate_cost(model_id: str, input_tokens: int, output_tokens: int) -> float:
    """Estimate cost for a model call."""
    info = MODEL_REGISTRY.get(model_id)
    if not info:
        return 0.0

    input_cost = (input_tokens / 1000) * info.cost_per_1k_input
    output_cost = (output_tokens / 1000) * info.cost_per_1k_output
    return input_cost + output_cost
