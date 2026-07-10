"""Output validation for agent responses against Pydantic schemas."""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Type
from dataclasses import dataclass
from enum import Enum

from pydantic import BaseModel, ValidationError

from ai.agents.base import AgentError


class ValidationSeverity(str, Enum):
    """Severity of validation issue."""
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


@dataclass
class ValidationIssue:
    """Single validation issue."""
    field: str
    message: str
    severity: ValidationSeverity
    expected_type: Optional[str] = None
    received_value: Any = None
    path: str = ""


@dataclass
class ValidationResult:
    """Result of output validation."""
    is_valid: bool
    issues: List[ValidationIssue] = None
    parsed_output: Optional[BaseModel] = None
    raw_output: str = ""

    def __post_init__(self):
        if self.issues is None:
            self.issues = []

    def add_error(self, field: str, message: str, **kwargs):
        self.is_valid = False
        self.issues.append(ValidationIssue(field=field, message=message, severity=ValidationSeverity.ERROR, **kwargs))

    def add_warning(self, field: str, message: str, **kwargs):
        self.issues.append(ValidationIssue(field=field, message=message, severity=ValidationSeverity.WARNING, **kwargs))

    def get_errors(self) -> List[ValidationIssue]:
        return [i for i in self.issues if i.severity == ValidationSeverity.ERROR]

    def get_warnings(self) -> List[ValidationIssue]:
        return [i for i in self.issues if i.severity == ValidationSeverity.WARNING]


class OutputValidator:
    """Validates agent outputs against Pydantic schemas with auto-repair."""

    def __init__(self, schema_class: Type[BaseModel], strict: bool = False):
        self.schema_class = schema_class
        self.strict = strict
        self.json_pattern = re.compile(r'```(?:json)?\s*(\{.*?\})\s*```', re.DOTALL)

    def validate(self, raw_output: str) -> ValidationResult:
        """Validate raw output against schema."""
        result = ValidationResult(is_valid=True, raw_output=raw_output)

        # Extract JSON from output
        json_str = self._extract_json(raw_output)
        if not json_str:
            result.add_error("root", "No valid JSON found in output")
            return result

        # Parse JSON
        try:
            data = json.loads(json_str)
        except json.JSONDecodeError as e:
            result.add_error("root", f"Invalid JSON: {e}")
            return result

        # Validate against schema
        try:
            parsed = self.schema_class(**data)
            result.parsed_output = parsed
            result.is_valid = True
        except ValidationError as e:
            for error in e.errors():
                field_path = ".".join(str(loc) for loc in error["loc"])
                result.add_error(
                    field_path,
                    error["msg"],
                    expected_type=error.get("type"),
                    received_value=error.get("input"),
                    path=field_path,
                )
            result.is_valid = False

        return result

    def validate_and_repair(self, raw_output: str, max_attempts: int = 3) -> ValidationResult:
        """Validate with automatic repair attempts."""
        result = self.validate(raw_output)

        if result.is_valid:
            return result

        # Try repair strategies
        for attempt in range(max_attempts):
            repaired = self._attempt_repair(raw_output, result)
            if repaired:
                result = self.validate(repaired)
                if result.is_valid:
                    result.add_warning("root", f"Output repaired on attempt {attempt + 1}")
                    return result

        return result

    def _extract_json(self, text: str) -> Optional[str]:
        """Extract JSON from text, handling markdown code blocks."""
        # Try markdown code blocks first
        matches = self.json_pattern.findall(text)
        if matches:
            # Return the largest match (most likely to be complete)
            return max(matches, key=len)

        # Try to find JSON-like structure
        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end != -1 and end > start:
            return text[start:end+1]

        return None

    def _attempt_repair(self, raw_output: str, result: ValidationResult) -> Optional[str]:
        """Attempt to repair invalid output."""
        json_str = self._extract_json(raw_output)
        if not json_str:
            return None

        try:
            data = json.loads(json_str)
        except json.JSONDecodeError:
            return None

        # Get schema field definitions
        schema_fields = self.schema_class.model_fields

        # Repair missing required fields
        for field_name, field_info in schema_fields.items():
            if field_name not in data and field_info.is_required():
                # Add default or empty value based on type
                data[field_name] = self._get_default_value(field_info)

        # Remove extra fields not in schema (if strict)
        if self.strict:
            allowed_fields = set(schema_fields.keys())
            data = {k: v for k, v in data.items() if k in allowed_fields}

        # Fix common type issues
        for field_name, field_info in schema_fields.items():
            if field_name in data:
                data[field_name] = self._coerce_type(data[field_name], field_info)

        return json.dumps(data)

    def _get_default_value(self, field_info) -> Any:
        """Get default value for a field based on its type."""
        from typing import get_origin, get_args

        annotation = field_info.annotation
        origin = get_origin(annotation)
        args = get_args(annotation)

        if origin is list:
            return []
        elif origin is dict:
            return {}
        elif origin is type(None) or (origin is not None and type(None) in args):
            return None
        elif annotation is str:
            return ""
        elif annotation is int:
            return 0
        elif annotation is float:
            return 0.0
        elif annotation is bool:
            return False
        else:
            return None

    def _coerce_type(self, value: Any, field_info) -> Any:
        """Coerce value to expected type."""
        from typing import get_origin, get_args

        annotation = field_info.annotation
        origin = get_origin(annotation)
        args = get_args(annotation)

        if value is None:
            return self._get_default_value(field_info)

        if origin is list and not isinstance(value, list):
            if isinstance(value, str):
                try:
                    return json.loads(value)
                except json.JSONDecodeError:
                    return [value]
            return [value]

        if origin is dict and not isinstance(value, dict):
            if isinstance(value, str):
                try:
                    return json.loads(value)
                except json.JSONDecodeError:
                    return {}
            return {}

        if annotation is int and isinstance(value, (str, float)):
            try:
                return int(float(value))
            except (ValueError, TypeError):
                return 0

        if annotation is float and isinstance(value, (str, int)):
            try:
                return float(value)
            except (ValueError, TypeError):
                return 0.0

        if annotation is bool and isinstance(value, str):
            return value.lower() in ("true", "1", "yes", "on")

        if annotation is str and not isinstance(value, str):
            return str(value)

        return value