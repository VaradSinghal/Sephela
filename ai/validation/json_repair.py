"""
ai/validation/json_repair.py — JSON extraction and repair for malformed LLM output.

LLMs occasionally produce JSON that is technically invalid: trailing commas,
single-quoted strings, truncated output, or JSON embedded in markdown fences.
This module provides a best-effort repair pipeline that is applied before
schema validation so we avoid unnecessary LLM re-calls for trivial formatting
issues.

Repair strategies (applied in order)
--------------------------------------
1. Strip leading/trailing non-JSON text (prose before/after the JSON object).
2. Extract from markdown code fences (```json ... ``` or ``` ... ```).
3. Remove JavaScript-style trailing commas.
4. Normalise single-quoted strings to double-quoted.
5. Fix unescaped control characters inside strings.
6. Truncation repair — add missing closing braces/brackets.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from typing import Any, Optional

_LOG = logging.getLogger("sephela.validation.json_repair")

# Regex patterns
_FENCE_RE = re.compile(r"```(?:json)?\s*(\{[\s\S]*?\})\s*```", re.DOTALL)
_TRAILING_COMMA_RE = re.compile(r",\s*([\}\]])")
_SINGLE_QUOTE_KEY_RE = re.compile(r"'([^']+)'\s*:")
_CTRL_CHAR_RE = re.compile(r'[\x00-\x1f\x7f](?=[^"\\]*")')


@dataclass
class RepairResult:
    """Outcome of a JSON repair attempt."""

    success: bool
    data: Optional[Any] = None                 # parsed Python object if successful
    repaired_text: Optional[str] = None        # repaired JSON string
    original_text: str = ""
    strategy_used: Optional[str] = None        # which strategy worked
    error: Optional[str] = None


class JSONRepair:
    """
    Multi-strategy JSON repair pipeline.

    Usage::

        result = JSONRepair.repair(raw_llm_output)
        if result.success:
            data = result.data
    """

    @classmethod
    def repair(cls, text: str) -> RepairResult:
        """
        Attempt to extract and repair JSON from raw LLM output.

        Args:
            text: Raw LLM response string.

        Returns:
            RepairResult with success flag and parsed data.
        """
        original = text
        strategies = [
            ("direct_parse", cls._try_direct),
            ("fence_extract", cls._try_fence_extract),
            ("brace_extract", cls._try_brace_extract),
            ("trailing_comma_fix", cls._try_trailing_comma),
            ("single_quote_fix", cls._try_single_quote),
            ("truncation_repair", cls._try_truncation_repair),
            ("aggressive_extract", cls._try_aggressive_extract),
        ]

        for name, strategy in strategies:
            result = strategy(text)
            if result.success:
                result.strategy_used = name
                result.original_text = original
                if name != "direct_parse":
                    _LOG.debug("JSON repaired with strategy: %s", name)
                return result

        return RepairResult(
            success=False,
            original_text=original,
            error="All repair strategies failed",
        )

    # ------------------------------------------------------------------
    # Strategies
    # ------------------------------------------------------------------

    @staticmethod
    def _try_direct(text: str) -> RepairResult:
        """Attempt direct JSON parse — no transformation."""
        try:
            data = json.loads(text.strip())
            return RepairResult(success=True, data=data, repaired_text=text.strip())
        except json.JSONDecodeError:
            return RepairResult(success=False)

    @staticmethod
    def _try_fence_extract(text: str) -> RepairResult:
        """Extract JSON from markdown code fences."""
        matches = _FENCE_RE.findall(text)
        if not matches:
            return RepairResult(success=False)
        # Try longest match first (most complete)
        for candidate in sorted(matches, key=len, reverse=True):
            try:
                data = json.loads(candidate)
                return RepairResult(success=True, data=data, repaired_text=candidate)
            except json.JSONDecodeError:
                continue
        return RepairResult(success=False)

    @staticmethod
    def _try_brace_extract(text: str) -> RepairResult:
        """Find the first { ... } substring and try parsing it."""
        start = text.find("{")
        end = text.rfind("}")
        if start == -1 or end <= start:
            return RepairResult(success=False)
        candidate = text[start : end + 1]
        try:
            data = json.loads(candidate)
            return RepairResult(success=True, data=data, repaired_text=candidate)
        except json.JSONDecodeError:
            return RepairResult(success=False)

    @staticmethod
    def _try_trailing_comma(text: str) -> RepairResult:
        """Remove trailing commas before } or ]."""
        start = text.find("{")
        end = text.rfind("}")
        if start == -1 or end <= start:
            return RepairResult(success=False)
        candidate = text[start : end + 1]
        fixed = _TRAILING_COMMA_RE.sub(r"\1", candidate)
        try:
            data = json.loads(fixed)
            return RepairResult(success=True, data=data, repaired_text=fixed)
        except json.JSONDecodeError:
            return RepairResult(success=False)

    @staticmethod
    def _try_single_quote(text: str) -> RepairResult:
        """Convert single-quoted keys to double-quoted (Python dict → JSON)."""
        start = text.find("{")
        end = text.rfind("}")
        if start == -1 or end <= start:
            return RepairResult(success=False)
        candidate = text[start : end + 1]
        # Replace 'key': with "key":
        fixed = _SINGLE_QUOTE_KEY_RE.sub(r'"\1":', candidate)
        # Remove trailing commas after fixing
        fixed = _TRAILING_COMMA_RE.sub(r"\1", fixed)
        try:
            data = json.loads(fixed)
            return RepairResult(success=True, data=data, repaired_text=fixed)
        except json.JSONDecodeError:
            return RepairResult(success=False)

    @staticmethod
    def _try_truncation_repair(text: str) -> RepairResult:
        """
        Handle truncated JSON by counting unmatched braces/brackets and closing them.
        """
        start = text.find("{")
        if start == -1:
            return RepairResult(success=False)
        candidate = text[start:]

        depth_brace = 0
        depth_bracket = 0
        in_string = False
        escape_next = False

        for ch in candidate:
            if escape_next:
                escape_next = False
                continue
            if ch == "\\" and in_string:
                escape_next = True
                continue
            if ch == '"' and not escape_next:
                in_string = not in_string
                continue
            if in_string:
                continue
            if ch == "{":
                depth_brace += 1
            elif ch == "}":
                depth_brace -= 1
            elif ch == "[":
                depth_bracket += 1
            elif ch == "]":
                depth_bracket -= 1

        # Close unclosed structures
        suffix = "]" * max(0, depth_bracket) + "}" * max(0, depth_brace)
        if not suffix:
            return RepairResult(success=False)

        fixed = candidate.rstrip().rstrip(",") + suffix
        # Also fix trailing commas
        fixed = _TRAILING_COMMA_RE.sub(r"\1", fixed)
        try:
            data = json.loads(fixed)
            return RepairResult(success=True, data=data, repaired_text=fixed)
        except json.JSONDecodeError:
            return RepairResult(success=False)

    @staticmethod
    def _try_aggressive_extract(text: str) -> RepairResult:
        """
        Last-resort: try each { ... } substring from longest to shortest.
        """
        candidates: list[str] = []
        depth = 0
        start = -1
        for i, ch in enumerate(text):
            if ch == "{":
                if depth == 0:
                    start = i
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0 and start != -1:
                    candidates.append(text[start : i + 1])
                    start = -1

        for candidate in sorted(candidates, key=len, reverse=True):
            # Apply trailing-comma fix first
            fixed = _TRAILING_COMMA_RE.sub(r"\1", candidate)
            try:
                data = json.loads(fixed)
                return RepairResult(success=True, data=data, repaired_text=fixed)
            except json.JSONDecodeError:
                continue

        return RepairResult(success=False)
