"""PermissionAgent — capability grouping and the banking-risk weighting.

The deterministic analyzer here is the fallback a no-credential deployment relies on
for its permission verdict, and it could not run at all: it passed a bool into
``PermissionRisk.is_used_by_component``, which is a ``list[str]``, so every single
permission raised ``ValidationError``.
"""

from __future__ import annotations

from typing import Any

import pytest

from ai.agents.permission import (
    BANKING_HIGH_RISK,
    PERMISSION_GROUPS,
    PermissionAgent,
    _assess_permission_risk,
    _score_to_severity,
    analyze_permissions_deterministic,
)
from ai.schemas.base import Confidence, Severity


def _analyse(*permissions: str, code_context: dict[str, Any] | None = None):
    return analyze_permissions_deterministic(
        {"permissions": {"count": len(permissions), "permissions": list(permissions)}},
        code_context,
    )


class TestPrompt:
    def test_it_lists_the_declared_permissions(self, sample_evidence: dict[str, Any]) -> None:
        prompt = PermissionAgent().build_prompt(sample_evidence["static_evidence"], {})

        assert "android.permission.BIND_ACCESSIBILITY_SERVICE" in prompt


class TestItRunsAtAll:
    def test_a_single_permission_produces_a_risk(self) -> None:
        # The regression: this raised ValidationError for any non-empty permission list.
        analysis = _analyse("android.permission.BIND_ACCESSIBILITY_SERVICE")

        assert analysis.total_permissions == 1
        assert [r.permission for r in analysis.dangerous_permissions] == [
            "android.permission.BIND_ACCESSIBILITY_SERVICE"
        ]

    @pytest.mark.parametrize("permission", sorted(BANKING_HIGH_RISK))
    def test_every_banking_permission_can_be_assessed(self, permission: str) -> None:
        analysis = _analyse(permission)

        (risk,) = analysis.banking_relevant_permissions
        assert risk.permission == permission
        assert risk.protection_level == "dangerous"

    def test_no_permissions_is_a_valid_input(self) -> None:
        analysis = _analyse()

        assert analysis.total_permissions == 0
        assert analysis.findings == []
        # No banking permissions must not divide by zero.
        assert analysis.financial_risk_score == 0.0


class TestClassification:
    def test_a_banking_permission_is_dangerous(self) -> None:
        analysis = _analyse("android.permission.READ_SMS")

        assert [r.permission for r in analysis.dangerous_permissions] == [
            "android.permission.READ_SMS"
        ]

    def test_a_vendor_prefixed_permission_is_custom(self) -> None:
        analysis = _analyse("com.example.app.PRIVATE")

        assert [r.permission for r in analysis.custom_permissions] == ["com.example.app.PRIVATE"]

    def test_an_ordinary_permission_is_normal_and_raises_no_finding(self) -> None:
        analysis = _analyse("android.permission.INTERNET")

        assert [r.permission for r in analysis.normal_permissions] == [
            "android.permission.INTERNET"
        ]
        # Only dangerous/signature/custom permissions become findings — INTERNET on its
        # own says nothing, and a report full of it would bury the real signal.
        assert analysis.findings == []


class TestBankingRiskScore:
    def test_accessibility_alone_scores_at_the_top(self) -> None:
        # The permission a screen-reading overlay trojan actually needs.
        analysis = _analyse("android.permission.BIND_ACCESSIBILITY_SERVICE")

        assert analysis.financial_risk_score == pytest.approx(1.0)

    def test_a_benign_app_scores_zero(self) -> None:
        assert _analyse("android.permission.INTERNET").financial_risk_score == 0.0

    def test_more_banking_permissions_never_lowers_the_score_below_the_weakest(self) -> None:
        weakest = _analyse("android.permission.ACCESS_FINE_LOCATION").financial_risk_score
        combined = _analyse(
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
        ).financial_risk_score

        assert combined > weakest


class TestCodeCorroboration:
    def test_a_permission_confirmed_in_code_is_scored_higher(self) -> None:
        perm = "android.permission.RECORD_AUDIO"
        declared = _assess_permission_risk(perm, used_in_code=False)
        confirmed = _assess_permission_risk(perm, used_in_code=True)

        assert confirmed.risk_score > declared.risk_score
        assert confirmed.confidence is Confidence.very_high
        assert declared.confidence is Confidence.high

    def test_the_rationale_says_whether_code_usage_was_confirmed(self) -> None:
        perm = "android.permission.READ_SMS"

        assert "unconfirmed" in _assess_permission_risk(perm, False).rationale
        assert "Actively used" in _assess_permission_risk(perm, True).rationale

    def test_code_context_reaches_the_assessment(self) -> None:
        perm = "android.permission.READ_SMS"
        without = _analyse(perm)
        with_code = _analyse(perm, code_context={"summary": {"permissions_used": [perm]}})

        assert with_code.dangerous_permissions[0].confidence is Confidence.very_high
        assert without.dangerous_permissions[0].confidence is Confidence.high

    def test_a_score_never_exceeds_the_schema_bound(self) -> None:
        # Accessibility is already 1.0, and confirmed usage multiplies by 1.2.
        risk = _assess_permission_risk("android.permission.BIND_ACCESSIBILITY_SERVICE", True)

        assert risk.risk_score == 1.0


class TestGrouping:
    def test_sms_permissions_are_grouped_together(self) -> None:
        analysis = _analyse("android.permission.READ_SMS", "android.permission.RECEIVE_SMS")

        (group,) = analysis.permission_groups
        assert group.group_name == "SMS"
        assert {r.permission for r in group.permissions} == {
            "android.permission.READ_SMS",
            "android.permission.RECEIVE_SMS",
        }

    def test_a_group_with_no_matching_permissions_is_omitted(self) -> None:
        analysis = _analyse("android.permission.BIND_ACCESSIBILITY_SERVICE")

        assert "SMS" not in {g.group_name for g in analysis.permission_groups}

    def test_the_group_aggregate_is_the_mean_of_its_members(self) -> None:
        analysis = _analyse("android.permission.READ_SMS", "android.permission.RECEIVE_SMS")

        (group,) = analysis.permission_groups
        expected = sum(r.risk_score for r in group.permissions) / len(group.permissions)
        assert group.aggregate_risk == pytest.approx(expected)

    def test_every_group_in_the_table_is_non_empty(self) -> None:
        for name, perms in PERMISSION_GROUPS.items():
            assert perms, f"{name} lists no permissions, so it can never be reported"


class TestSeverityBanding:
    @pytest.mark.parametrize(
        ("score", "expected"),
        [
            (1.0, Severity.critical),
            (0.8, Severity.critical),
            (0.79, Severity.high),
            (0.6, Severity.high),
            (0.59, Severity.medium),
            (0.4, Severity.medium),
            (0.39, Severity.low),
            (0.2, Severity.low),
            (0.19, Severity.info),
            (0.0, Severity.info),
        ],
    )
    def test_the_boundaries_are_inclusive_at_the_bottom(
        self, score: float, expected: Severity
    ) -> None:
        assert _score_to_severity(score) is expected


class TestFindings:
    def test_a_finding_carries_the_mappings_a_report_needs(self) -> None:
        analysis = _analyse("android.permission.BIND_ACCESSIBILITY_SERVICE")

        (finding,) = analysis.findings
        assert finding.type == "permission_risk"
        assert finding.mitre_techniques
        assert finding.owasp_mobile
        assert finding.evidence_refs[0].extractor == "permissions"

    def test_findings_are_extracted_from_the_analysis(self) -> None:
        analysis = _analyse("android.permission.READ_SMS")

        assert PermissionAgent().extract_findings(analysis)
