"""Prompt management for GenAI agents."""

from ai.prompts.system_prompts import SYSTEM_PROMPTS, get_system_prompt
from ai.prompts.few_shot_examples import FEW_SHOT_EXAMPLES, get_few_shot

__all__ = [
    "SYSTEM_PROMPTS",
    "get_system_prompt",
    "FEW_SHOT_EXAMPLES",
    "get_few_shot",
]