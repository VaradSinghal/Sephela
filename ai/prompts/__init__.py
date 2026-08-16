"""Prompt management for GenAI agents.

The shared building blocks live in ``ai.prompts.shared``; they are re-exported here
so callers can say ``from ai.prompts import get_system_prompt`` without knowing the
layout. Per-agent prompt bodies are the ``*_prompt.md`` files alongside this module,
loaded by :class:`ai.prompts.prompt_manager.PromptManager`.
"""

from ai.prompts.shared.few_shot_examples import FEW_SHOT_EXAMPLES, get_few_shot
from ai.prompts.shared.system_prompts import SYSTEM_PROMPTS, get_system_prompt

__all__ = [
    "FEW_SHOT_EXAMPLES",
    "SYSTEM_PROMPTS",
    "get_few_shot",
    "get_system_prompt",
]
