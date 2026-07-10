"""Schema enforcement for structured LLM outputs."""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Type
from dataclasses import dataclass

from pydantic import BaseModel, ValidationError

from ai.validation.output_validator import OutputValidator, ValidationResult


@dataclass
class SchemaEnforcementResult:
    """Result of schema enforcement."""
    is_valid: bool
    validated_output: Optional[BaseModel] = None
    raw_output: str = ""
    errors: List[str] = None
    warnings: List[str] = None
    repair_attempts: int = 0

    def __post_init__(self):
        if self.errors is None:
            self.errors = []
        if self.warnings is None:
            self.warnings = []


class SchemaEnforcer:
    """Enforces Pydantic schemas on LLM outputs with validation and repair."""

    def __init__(
        self,
        schema_class: Type[BaseModel],
        enable_repair: bool = True,
        max_repair_attempts: int = 3,
        strict_mode: bool = False,
    ):
        self.validator = OutputValidator(schema_class, strict=strict_mode)
        self.enable_repair = enable_repair
        self.max_repair_attempts = max_repair_attempts
        self.strict_mode = strict_mode

    def enforce(self, raw_output: str) -> SchemaEnforcementResult:
        """Enforce schema on raw output."""
        if self.enable_repair:
            validation_result = self.validator.validate_and_repair(raw_output, self.max_repair_attempts)
            repair_attempts = self.max_repair_attempts if not validation_result.is_valid else 0
        else:
            validation_result = self.validator.validate(raw_output)
            repair_attempts = 0

        return SchemaEnforcementResult(
            is_valid=validation_result.is_valid,
            validated_output=validation_result.parsed_output,
            raw_output=raw_output,
            errors=[i.message for i in validation_result.get_errors()],
            warnings=[i.message for i in validation_result.get_warnings()],
            repair_attempts=repair_attempts,
        )

    def enforce_batch(self, outputs: List[str]) -> List[SchemaEnforcementResult]:
        """Enforce schema on multiple outputs."""
        return [self.enforce(output) for output in outputs]

    def get_schema_requirements(self) -> Dict[str, Any]:
        """Get schema requirements as a dictionary for prompt inclusion."""
        return self.validator.schema_class.model_json_schema()

    def create_example_output(self) -> str:
        """Create an example valid output for few-shot prompting."""
        schema = self.validator.schema_class
        example = {}

        for field_name, field_info in schema.model_fields.items():
            example[field_name] = self._generate_example_value(field_info)

        return json.dumps(example, indent=2)

    def _generate_example_value(self, field_info) -> Any:
        """Generate example value for a field."""
        from typing import get_origin, get_args

        annotation = field_info.annotation
        origin = get_origin(annotation)
        args = get_args(annotation)

        if field_info.default is not None and field_info.default != ...:
            return field_info.default

        if origin is list:
            item_type = args[0] if args else str
            return [self._generate_example_value_for_type(item_type)]
        elif origin is dict:
            key_type, value_type = args if len(args) == 2 else (str, str)
            return {self._generate_example_value_for_type(key_type): self._generate_example_value_for_type(value_type)}
        elif origin is type(None) or (origin is not None and type(None) in args):
            return None
        else:
            return self._generate_example_value_for_type(annotation)

    def _generate_example_value_for_type(self, annotation) -> Any:
        """Generate example for a type annotation."""
        if annotation is str:
            return "example_string"
        elif annotation is int:
            return 42
        elif annotation is float:
            return 3.14
        elif annotation is bool:
            return True
        else:
            return "example"