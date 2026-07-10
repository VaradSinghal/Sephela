"""
ai/validation/response_validator.py — End-to-end response validation for agent outputs.

This module is the single entry point that agents call after receiving an LLM
response.  It coordinates:

1. JSON repair (via json_repair.JSONRepair)
2. Schema validation (via schema_validator.SchemaValidator)
3. Evidence reference validation
4. Business-rule validation (confidence bounds, required MITRE mappings, etc.)
5. Structured logging of all outcomes

Usage from an agent::

    from ai.validation.response_validator import ResponseValidator
    from ai.schemas.results import ManifestAnalysisResult

    validator = ResponseValidator(ManifestAnalysisResult)
    validated = validator.validate(llm_raw_text, evidence=state["evidence"])
    if validated.is_usable:
        result = validated.model_instance  # ManifestAnalysisResult
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any, Optional, Type

from pydantic import BaseModel

from ai.validation.json_repair import JSONRepair
from ai.validation.schema_validator import (
    FieldIssue,
    IssueSeverity,
    SchemaValidator,
    ValidationReport,
    ValidationStatus,
)

_LOG = logging.getLogger("sephela.validation.response")


# ---------------------------------------------------------------------------
# Business-rule validators (pluggable)
# ---------------------------------------------------------------------------


class _RuleViolation:
    def __init__(self, field: str, message: str, severity: IssueSeverity) -> None:
        self.field = field
        self.message = message
        self.severity = severity


def _check_mitre_mappings(data: dict[str, Any]) -> list[_RuleViolation]:
    """Warn when a high/critical finding has no MITRE technique mapped."""
    violations: list[_RuleViolation] = []
    findings = data.get("findings", [])
    for i, f in enumerate(findings):
        if not isinstance(f, dict):
            continue
        severity = f.get("severity", "")
        mitre = f.get("mitre_techniques") or f.get("mitre_mappings") or []
        if severity in ("critical", "high") and not mitre:
            violations.append(_RuleViolation(
                f"findings[{i}].mitre_techniques",
                f"Finding '{f.get('title', i)}' is {severity} but has no MITRE mappings",
                IssueSeverity.WARNING,
            ))
    return violations


def _check_evidence_refs(data: dict[str, Any], evidence: Optional[dict[str, Any]]) -> list[_RuleViolation]:
    """Validate that evidence_refs point to extractors present in the evidence envelope."""
    if not evidence:
        return []
    violations: list[_RuleViolation] = []
    available_extractors = set(evidence.keys())
    for field_name in ("evidence_references", "evidence_refs"):
        refs = data.get(field_name, [])
        for i, ref in enumerate(refs):
            if not isinstance(ref, dict):
                continue
            extractor = ref.get("extractor", "")
            if extractor and extractor not in available_extractors:
                violations.append(_RuleViolation(
                    f"{field_name}[{i}].extractor",
                    f"Evidence reference points to unknown extractor '{extractor}'. "
                    f"Available: {sorted(available_extractors)}",
                    IssueSeverity.WARNING,
                ))
    return violations


def _check_confidence_range(data: dict[str, Any]) -> list[_RuleViolation]:
    """Ensure overall confidence is within [0, 1]."""
    violations: list[_RuleViolation] = []
    for field_name in ("confidence_overall", "confidence", "classification_confidence"):
        val = data.get(field_name)
        if val is not None and isinstance(val, (int, float)):
            if not (0.0 <= float(val) <= 1.0):
                violations.append(_RuleViolation(
                    field_name,
                    f"Confidence {val} outside [0.0, 1.0]",
                    IssueSeverity.ERROR,
                ))
    return violations


def _check_score_range(data: dict[str, Any]) -> list[_RuleViolation]:
    """Ensure risk score is within [0, 100]."""
    violations: list[_RuleViolation] = []
    for field_name in ("score", "permission_risk_score"):
        val = data.get(field_name)
        if val is not None and isinstance(val, (int, float)):
            if not (0.0 <= float(val) <= 100.0):
                violations.append(_RuleViolation(
                    field_name,
                    f"Score {val} outside [0.0, 100.0]",
                    IssueSeverity.ERROR,
                ))
    return violations


# ---------------------------------------------------------------------------
# ResponseValidator
# ---------------------------------------------------------------------------


class ResponseValidator:
    """
    End-to-end validator for a single agent's LLM response.

    Args:
        schema:        The Pydantic model class to validate against.
        allow_partial: Whether to accept partially valid models (missing optional fields).
        evidence:      The Evidence Envelope dict for cross-reference validation.
    """

    _BUSINESS_RULES = [
        _check_confidence_range,
        _check_score_range,
        _check_mitre_mappings,
    ]

    def __init__(
        self,
        schema: Type[BaseModel],
        allow_partial: bool = True,
    ) -> None:
        self._schema_validator = SchemaValidator(schema, allow_partial=allow_partial)
        self._schema = schema

    def validate(
        self,
        raw_text: str,
        evidence: Optional[dict[str, Any]] = None,
        agent_name: str = "",
    ) -> ValidationReport:
        """
        Validate raw LLM output against the schema and business rules.

        Args:
            raw_text:   The raw string returned by the LLM.
            evidence:   Evidence envelope for cross-reference checks.
            agent_name: Agent name for structured log entries.

        Returns:
            ValidationReport — always returns, never raises.
        """
        # Step 1 — Schema validation (includes JSON repair internally)
        report = self._schema_validator.validate(raw_text)

        # Step 2 — Business rules (only when we have a parsed dict)
        if report.is_usable and report.model_instance is not None:
            try:
                data = report.model_instance.model_dump()
                violations: list[_RuleViolation] = []
                for rule in self._BUSINESS_RULES:
                    violations.extend(rule(data))
                if evidence:
                    violations.extend(_check_evidence_refs(data, evidence))
                for v in violations:
                    report.issues.append(FieldIssue(
                        field_path=v.field,
                        message=v.message,
                        severity=v.severity,
                    ))
            except Exception as exc:  # noqa: BLE001
                _LOG.warning("Business rule check failed: %s", exc)

        # Step 3 — Structured log
        _LOG.info(
            '{"event":"validation","agent":"%s","schema":"%s",%s}',
            agent_name,
            self._schema.__name__,
            report.summary().replace('"', '\\"'),
        )

        if not report.is_usable:
            _LOG.error(
                '{"event":"validation_failure","agent":"%s","errors":%s}',
                agent_name,
                json.dumps([i.message for i in report.errors[:5]]),
            )

        return report

    def validate_dict(
        self,
        data: dict[str, Any],
        evidence: Optional[dict[str, Any]] = None,
        agent_name: str = "",
    ) -> ValidationReport:
        """
        Validate a pre-parsed dictionary (skip JSON repair).

        Useful when the LLM gateway already parsed the JSON.
        """
        report = self._schema_validator.validate_dict(data)

        if report.is_usable and report.model_instance is not None:
            try:
                violations: list[_RuleViolation] = []
                for rule in self._BUSINESS_RULES:
                    violations.extend(rule(data))
                if evidence:
                    violations.extend(_check_evidence_refs(data, evidence))
                for v in violations:
                    report.issues.append(FieldIssue(
                        field_path=v.field,
                        message=v.message,
                        severity=v.severity,
                    ))
            except Exception as exc:  # noqa: BLE001
                _LOG.warning("Business rule check failed: %s", exc)

        _LOG.info(
            '{"event":"validation","agent":"%s","schema":"%s",%s}',
            agent_name,
            self._schema.__name__,
            report.summary().replace('"', '\\"'),
        )

        return report
