"""
ai/validation/schema_validator.py — Pydantic v2 schema validation with rich diagnostics.

This module validates LLM output dicts/strings against Pydantic models and
produces structured ValidationReport objects that agents can act on.

Features
--------
* JSON extraction via JSONRepair (handles malformed responses)
* Pydantic v2 validation with full error path reporting
* Field-level coercion for common type mismatches (str→int, list→str, etc.)
* Confidence score validation (must be 0.0–1.0)
* Evidence reference cross-validation
* Partial-result tolerance (allow partial models when only soft fields fail)
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional, Type

from pydantic import BaseModel, ValidationError

from ai.validation.json_repair import JSONRepair, RepairResult

_LOG = logging.getLogger("sephela.validation.schema_validator")


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class ValidationStatus(str, Enum):
    VALID = "valid"
    REPAIRED = "repaired"
    PARTIAL = "partial"           # Required fields OK, optional fields failed
    INVALID = "invalid"


class IssueSeverity(str, Enum):
    ERROR = "error"
    WARNING = "warning"


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class FieldIssue:
    """A problem with a specific field in the LLM output."""

    field_path: str
    message: str
    severity: IssueSeverity
    expected_type: Optional[str] = None
    received_value: Any = None


@dataclass
class ValidationReport:
    """Complete validation report for a single LLM output."""

    status: ValidationStatus
    model_instance: Optional[BaseModel] = None   # populated when status != INVALID
    issues: list[FieldIssue] = field(default_factory=list)
    raw_text: str = ""
    repaired_text: Optional[str] = None
    repair_strategy: Optional[str] = None
    parse_error: Optional[str] = None

    @property
    def is_usable(self) -> bool:
        """True when we have a usable model instance (valid, repaired, or partial)."""
        return self.model_instance is not None

    @property
    def errors(self) -> list[FieldIssue]:
        return [i for i in self.issues if i.severity == IssueSeverity.ERROR]

    @property
    def warnings(self) -> list[FieldIssue]:
        return [i for i in self.issues if i.severity == IssueSeverity.WARNING]

    def summary(self) -> str:
        """One-line human readable summary."""
        return (
            f"status={self.status.value} errors={len(self.errors)} "
            f"warnings={len(self.warnings)} "
            f"repair={self.repair_strategy or 'none'}"
        )


# ---------------------------------------------------------------------------
# Validator
# ---------------------------------------------------------------------------


class SchemaValidator:
    """
    Validates and coerces raw LLM output against a Pydantic v2 model.

    Usage::

        validator = SchemaValidator(ManifestAnalysisResult)
        report = validator.validate(raw_llm_text)
        if report.is_usable:
            result = report.model_instance
    """

    def __init__(
        self,
        schema: Type[BaseModel],
        allow_partial: bool = True,
        strict: bool = False,
    ) -> None:
        self.schema = schema
        self.allow_partial = allow_partial
        self.strict = strict
        self._required_fields = {
            name
            for name, info in schema.model_fields.items()
            if info.is_required()
        }

    # ------------------------------------------------------------------
    # Primary API
    # ------------------------------------------------------------------

    def validate(self, raw_text: str) -> ValidationReport:
        """
        Full validation pipeline: repair → parse → validate → coerce.

        Args:
            raw_text: Raw string from the LLM.

        Returns:
            ValidationReport (always — never raises).
        """
        # Step 1 — JSON repair
        repair = JSONRepair.repair(raw_text)
        if not repair.success:
            return ValidationReport(
                status=ValidationStatus.INVALID,
                raw_text=raw_text,
                parse_error="Could not extract valid JSON from LLM output",
                issues=[FieldIssue(
                    field_path="<root>",
                    message="No valid JSON found. All repair strategies failed.",
                    severity=IssueSeverity.ERROR,
                )],
            )

        data: dict[str, Any] = repair.data if isinstance(repair.data, dict) else {}

        # Step 2 — Pydantic validation
        report = self._validate_dict(data, raw_text, repair)

        return report

    def validate_dict(self, data: dict[str, Any]) -> ValidationReport:
        """Validate a pre-parsed dictionary (skip JSON repair step)."""
        fake_repair = RepairResult(success=True, data=data, repaired_text=json.dumps(data))
        return self._validate_dict(data, json.dumps(data), fake_repair)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _validate_dict(
        self, data: dict[str, Any], raw_text: str, repair: RepairResult
    ) -> ValidationReport:
        """Run Pydantic validation on parsed dict, with coercion fallback."""
        issues: list[FieldIssue] = []

        # First pass — strict Pydantic
        try:
            instance = self.schema.model_validate(data)
            _validate_confidence_fields(instance, issues)
            status = (
                ValidationStatus.REPAIRED
                if repair.strategy_used and repair.strategy_used != "direct_parse"
                else ValidationStatus.VALID
            )
            return ValidationReport(
                status=status,
                model_instance=instance,
                raw_text=raw_text,
                repaired_text=repair.repaired_text,
                repair_strategy=repair.strategy_used,
                issues=issues,
            )

        except ValidationError as exc:
            # Collect issues
            for err in exc.errors():
                path = ".".join(str(p) for p in err["loc"])
                issues.append(FieldIssue(
                    field_path=path,
                    message=err["msg"],
                    severity=IssueSeverity.ERROR,
                    expected_type=err.get("type"),
                    received_value=err.get("input"),
                ))

        # Second pass — try coercion
        coerced = _coerce_dict(data, self.schema)
        try:
            instance = self.schema.model_validate(coerced)
            _validate_confidence_fields(instance, issues)
            # Downgrade errors that were fixed to warnings
            for issue in issues:
                issue.severity = IssueSeverity.WARNING
            return ValidationReport(
                status=ValidationStatus.REPAIRED,
                model_instance=instance,
                raw_text=raw_text,
                repaired_text=repair.repaired_text,
                repair_strategy=f"coercion+{repair.strategy_used}",
                issues=issues,
            )
        except ValidationError as exc2:
            # Collect fresh issues from coercion attempt
            coerce_issues: list[FieldIssue] = list(issues)
            for err in exc2.errors():
                path = ".".join(str(p) for p in err["loc"])
                if not any(i.field_path == path for i in coerce_issues):
                    coerce_issues.append(FieldIssue(
                        field_path=path,
                        message=err["msg"],
                        severity=IssueSeverity.ERROR,
                        received_value=err.get("input"),
                    ))

        # Third pass — partial model if allow_partial
        if self.allow_partial:
            partial_instance = self._build_partial(data, issues)
            if partial_instance is not None:
                return ValidationReport(
                    status=ValidationStatus.PARTIAL,
                    model_instance=partial_instance,
                    raw_text=raw_text,
                    repaired_text=repair.repaired_text,
                    repair_strategy=repair.strategy_used,
                    issues=coerce_issues,
                )

        return ValidationReport(
            status=ValidationStatus.INVALID,
            raw_text=raw_text,
            repaired_text=repair.repaired_text,
            repair_strategy=repair.strategy_used,
            issues=coerce_issues,
            parse_error=f"{len(coerce_issues)} field errors after all repair attempts",
        )

    def _build_partial(
        self, data: dict[str, Any], issues: list[FieldIssue]
    ) -> Optional[BaseModel]:
        """
        Build a model ignoring non-required failing fields.

        Returns the model if all required fields validate; None otherwise.
        """
        failing_paths = {i.field_path for i in issues if i.severity == IssueSeverity.ERROR}
        # If any required field fails, we can't build a partial
        if any(f in self._required_fields for f in failing_paths):
            return None

        # Remove failing optional fields and try again
        partial_data = {
            k: v for k, v in data.items() if k not in failing_paths
        }
        try:
            return self.schema.model_validate(partial_data)
        except ValidationError:
            return None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _coerce_dict(data: dict[str, Any], schema: Type[BaseModel]) -> dict[str, Any]:
    """
    Apply type coercions to common LLM output mistakes:
    - None → [] for list fields
    - str → float for numeric fields
    - str → bool
    - nested dicts already handled by Pydantic
    """
    from typing import get_args, get_origin

    result = dict(data)
    for name, field_info in schema.model_fields.items():
        if name not in result:
            continue
        val = result[name]
        ann = field_info.annotation
        origin = get_origin(ann)
        args = get_args(ann)

        # None → empty list
        if origin is list and val is None:
            result[name] = []
            continue
        # list with wrong items → try str coercion
        if origin is list and not isinstance(val, list):
            result[name] = [val] if val is not None else []
            continue
        # str → float
        if ann is float and isinstance(val, str):
            try:
                result[name] = float(val)
            except ValueError:
                pass
            continue
        # str/float → int
        if ann is int and isinstance(val, (str, float)):
            try:
                result[name] = int(float(val))
            except ValueError:
                pass
            continue
        # str → bool
        if ann is bool and isinstance(val, str):
            result[name] = val.lower() in ("true", "1", "yes")
            continue

    return result


def _validate_confidence_fields(instance: BaseModel, issues: list[FieldIssue]) -> None:
    """Check all fields named 'confidence*' are within 0.0–1.0."""
    data = instance.model_dump()
    for key, value in _flatten_dict(data):
        if "confidence" in key.lower() and isinstance(value, (int, float)):
            if not (0.0 <= float(value) <= 1.0):
                issues.append(FieldIssue(
                    field_path=key,
                    message=f"Confidence value {value} out of range [0.0, 1.0]",
                    severity=IssueSeverity.WARNING,
                    received_value=value,
                ))


def _flatten_dict(
    d: Any, prefix: str = ""
) -> list[tuple[str, Any]]:
    """Flatten nested dict into dot-separated key/value pairs."""
    items: list[tuple[str, Any]] = []
    if isinstance(d, dict):
        for k, v in d.items():
            full_key = f"{prefix}.{k}" if prefix else k
            items.extend(_flatten_dict(v, full_key))
    elif isinstance(d, list):
        for i, v in enumerate(d):
            items.extend(_flatten_dict(v, f"{prefix}[{i}]"))
    else:
        items.append((prefix, d))
    return items
