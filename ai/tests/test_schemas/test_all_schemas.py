"""Tests for all schema definitions."""

import pytest
from pydantic import ValidationError

from ai.schemas.base import Finding, Severity, Confidence, EvidenceRef
from ai.schemas.manifest import ManifestAnalysis, ComponentInfo, PermissionFinding
from ai.schemas.permission import PermissionAnalysis, PermissionRisk, PermissionGroupRisk
from ai.schemas.code import CodeAnalysis, CodeSummary, ClassInfo, MethodInfo
from ai.schemas.api import APIAnalysis, APICall, DangerousAPI
from ai.schemas.network import NetworkAnalysis, NetworkConnection, DomainIntel
from ai.schemas.threat_intel import ThreatIntelAnalysis, IOCMatch, MalwareFamily
from ai.schemas.risk import RiskAnalysis, RiskFactor, RiskBreakdown, RiskTier
from ai.schemas.report import AnalysisReport, ExecutiveSummary, ReportFormat


class TestBaseSchemas:
    """Test base schema classes."""

    def test_finding_creation(self):
        finding = Finding(
            id="test_1",
            type="test",
            severity=Severity.high,
            confidence=Confidence.high,
            title="Test Finding",
            description="Test description",
        )
        assert finding.id == "test_1"
        assert finding.severity == Severity.high

    def test_severity_ordering(self):
        assert Severity.critical > Severity.high
        assert Severity.high > Severity.medium
        assert Severity.medium > Severity.low
        assert Severity.low > Severity.info

    def test_confidence_ordering(self):
        assert Confidence.very_high > Confidence.high
        assert Confidence.high > Confidence.medium
        assert Confidence.medium > Confidence.low

    def test_evidence_ref(self):
        ref = EvidenceRef(extractor="manifest", path="permissions")
        assert ref.extractor == "manifest"
        assert ref.path == "permissions"


class TestManifestSchemas:
    """Test manifest analysis schemas."""

    def test_component_info(self):
        comp = ComponentInfo(
            name="MainActivity",
            component_type="activity",
            exported=True,
            intent_filters=[{"action": "android.intent.action.MAIN"}],
        )
        assert comp.name == "MainActivity"
        assert comp.exported is True

    def test_permission_finding(self):
        finding = PermissionFinding(
            id="perm:test",
            type="permission",
            severity=Severity.high,
            confidence=Confidence.high,
            title="Test permission",
            description="Test",
            permission_name="android.permission.TEST",
            protection_level="dangerous",
            risk_rationale="Test rationale",
        )
        assert finding.permission_name == "android.permission.TEST"

    def test_manifest_analysis(self):
        analysis = ManifestAnalysis(
            package_name="com.example.test",
            debuggable=True,
            allow_backup=True,
            exported_component_count=2,
            dangerous_permission_count=3,
            critical_findings=1,
            high_findings=2,
        )
        assert analysis.package_name == "com.example.test"
        assert analysis.debuggable is True


class TestPermissionSchemas:
    """Test permission analysis schemas."""

    def test_permission_risk(self):
        risk = PermissionRisk(
            permission="android.permission.TEST",
            protection_level="dangerous",
            risk_score=0.8,
            severity=Severity.high,
            confidence=Confidence.high,
            rationale="Test rationale",
        )
        assert risk.risk_score == 0.8
        assert risk.severity == Severity.high

    def test_permission_group_risk(self):
        group = PermissionGroupRisk(
            group_name="SMS",
            permissions=[],
            aggregate_risk=0.9,
            severity=Severity.critical,
            capabilities_enabled=["intercept_2fa", "send_sms"],
        )
        assert group.group_name == "SMS"
        assert "intercept_2fa" in group.capabilities_enabled

    def test_permission_analysis(self):
        analysis = PermissionAnalysis(
            total_permissions=10,
            critical_count=1,
            high_count=3,
            financial_risk_score=0.85,
        )
        assert analysis.total_permissions == 10
        assert analysis.financial_risk_score == 0.85


class TestCodeSchemas:
    """Test code analysis schemas."""

    def test_method_info(self):
        method = MethodInfo(
            class_name="TestClass",
            method_name="testMethod",
            return_type="void",
            parameters=["String", "int"],
            access_flags=["public"],
            is_constructor=False,
        )
        assert method.method_name == "testMethod"
        assert len(method.parameters) == 2

    def test_class_info(self):
        cls = ClassInfo(
            class_name="TestClass",
            superclass="Object",
            interfaces=["Serializable"],
            methods=[MethodInfo(class_name="TestClass", method_name="method1", return_type="void")],
        )
        assert cls.class_name == "TestClass"
        assert len(cls.methods) == 1

    def test_code_summary(self):
        summary = CodeSummary(
            total_classes=100,
            total_methods=500,
            app_classes=50,
            app_methods=250,
            entry_points=["MainActivity"],
            network_apis=["OkHttp"],
            crypto_apis=["Cipher"],
        )
        assert summary.total_classes == 100
        assert summary.app_classes == 50

    def test_code_analysis(self):
        analysis = CodeAnalysis(
            summary=CodeSummary(total_classes=10),
            findings=[],
        )
        assert analysis.summary.total_classes == 10


class TestAPISchemas:
    """Test API analysis schemas."""

    def test_api_call(self):
        call = APICall(
            api_class="WindowManager",
            api_method="addView",
            api_package="android.view",
            call_sites=["MainActivity.onCreate"],
            data_flow=["view_param"],
            is_reflection=False,
            is_dynamic_loading=False,
            severity=Severity.high,
            confidence=Confidence.high,
            mitre_techniques=["T1417.002"],
            owasp_categories=["M1"],
        )
        assert call.api_method == "addView"
        assert "MainActivity.onCreate" in call.call_sites

    def test_dangerous_api(self):
        api = DangerousAPI(
            category="overlay_attack",
            severity=Severity.critical,
            description="Overlay attack API",
            mitre_techniques=["T1417.002"],
            owasp_categories=["M1"],
            matched_apis=["WindowManager.addView"],
        )
        assert api.category == "overlay_attack"
        assert api.severity == Severity.critical


class TestNetworkSchemas:
    """Test network analysis schemas."""

    def test_network_connection(self):
        conn = NetworkConnection(
            host="example.com",
            port=443,
            protocol="https",
            source="string",
            context="API endpoint",
            is_suspicious=False,
        )
        assert conn.host == "example.com"
        assert conn.protocol == "https"

    def test_domain_intel(self):
        intel = DomainIntel(
            domain="malicious.tk",
            is_malicious=True,
            categories=["malware", "c2"],
            reputation_score=0.9,
            is_dga=False,
            is_newly_registered=True,
        )
        assert intel.is_malicious is True
        assert intel.reputation_score == 0.9

    def test_network_analysis(self):
        analysis = NetworkAnalysis(
            domains=["example.com", "malicious.tk"],
            ips=["1.2.3.4"],
            findings=[],
            malicious_domain_count=1,
            critical_findings=0,
            high_findings=1,
        )
        assert len(analysis.domains) == 2
        assert analysis.malicious_domain_count == 1


class TestThreatIntelSchemas:
    """Test threat intelligence schemas."""

    def test_ioc_match(self):
        match = IOCMatch(
            indicator="malicious.tk",
            indicator_type="domain",
            source="OTX",
            confidence=Confidence.high,
            severity=Severity.high,
            tags=["malware", "banking"],
            malware_families=["Anubis"],
        )
        assert match.indicator == "malicious.tk"
        assert "Anubis" in match.malware_families

    def test_malware_family(self):
        family = MalwareFamily(
            family_name="Anubis",
            aliases=["BankBot"],
            confidence=Confidence.very_high,
            description="Banking trojan",
            mitre_techniques=["T1417", "T1636.004"],
            target_sectors=["financial"],
        )
        assert family.family_name == "Anubis"
        assert family.confidence == Confidence.very_high

    def test_threat_intel_analysis(self):
        analysis = ThreatIntelAnalysis(
            total_ioc_matches=5,
            family_attributions=1,
            critical_findings=2,
        )
        assert analysis.total_ioc_matches == 5


class TestRiskSchemas:
    """Test risk scoring schemas."""

    def test_risk_factor(self):
        factor = RiskFactor(
            factor_id="static_permissions",
            name="Static Permissions",
            category="static",
            weight=0.15,
            raw_score=80.0,
            weighted_contribution=12.0,
            evidence_refs=[],
            description="Permission risk",
            mitre_techniques=["T1417"],
            owasp_categories=["M1"],
        )
        assert factor.weight == 0.15
        assert factor.weighted_contribution == 12.0

    def test_risk_breakdown(self):
        breakdown = RiskBreakdown(
            factors=[],
            total_weight=1.0,
            base_score=75.0,
            final_score=85.0,
            scoring_version="1.0",
            computed_at="2024-01-01T00:00:00Z",
            confidence=0.9,
        )
        assert breakdown.final_score == 85.0

    def test_risk_tier(self):
        assert RiskTier.from_score(95) == RiskTier.critical
        assert RiskTier.from_score(75) == RiskTier.malicious
        assert RiskTier.from_score(50) == RiskTier.suspicious
        assert RiskTier.from_score(20) == RiskTier.benign

    def test_risk_analysis(self):
        analysis = RiskAnalysis(
            score=85.0,
            tier=RiskTier.malicious,
            confidence=0.9,
            breakdown=RiskBreakdown(
                factors=[],
                total_weight=1.0,
                base_score=85.0,
                final_score=85.0,
            ),
            primary_category="banking_trojan",
        )
        assert analysis.score == 85.0
        assert analysis.tier == RiskTier.malicious


class TestReportSchemas:
    """Test report generation schemas."""

    def test_executive_summary(self):
        summary = ExecutiveSummary(
            overview="Test overview",
            risk_score=85.0,
            risk_tier="malicious",
            key_findings=["Finding 1", "Finding 2"],
            business_impact="High impact",
            recommended_actions=["Action 1", "Action 2"],
        )
        assert summary.risk_score == 85.0
        assert len(summary.key_findings) == 2

    def test_report_format(self):
        assert ReportFormat.json == "json"
        assert ReportFormat.markdown == "markdown"
        assert ReportFormat.pdf == "pdf"
        assert ReportFormat.html == "html"
        assert ReportFormat.sarif == "sarif"

    def test_analysis_report(self):
        report = AnalysisReport(
            report_id="rpt_123",
            job_id="job_123",
            sample_sha256="a" * 64,
            executive_summary=ExecutiveSummary(
                overview="Test",
                risk_score=50.0,
                risk_tier="suspicious",
            ),
            technical_details={},
            evidence_catalog={},
            compliance_mapping={},
        )
        assert report.report_id == "rpt_123"
        assert report.sample_sha256 == "a" * 64


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
```"