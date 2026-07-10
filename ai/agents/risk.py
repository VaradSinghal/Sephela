"""Risk Scoring Agent - Computes explainable risk score from all agent findings."""

from __future__ import annotations

import json
from typing import Any

from pydantic import BaseModel

from ai.schemas.base import Finding, Severity, Confidence
from ai.schemas.risk import RiskAnalysis, RiskFactor, RiskBreakdown, RiskTier
from ai.agents.base import BaseAgent, AgentConfig, AgentResult


# Weight configuration for risk factors
RISK_WEIGHTS = {
    "static_manifest": 0.10,
    "static_permissions": 0.15,
    "static_code": 0.20,
    "static_api": 0.15,
    "static_network": 0.15,
    "threat_intel": 0.15,
    "dynamic_behavior": 0.10,  # For future dynamic analysis
}

# Severity to score mapping
SEVERITY_SCORES = {
    Severity.critical: 100,
    Severity.high: 75,
    Severity.medium: 50,
    Severity.low: 25,
    Severity.info: 10,
}

# Category to MITRE/OWASP mapping for narrative
CATEGORY_MITRE = {
    "overlay": ["T1417.002"],
    "accessibility": ["T1417.001"],
    "sms_intercept": ["T1636.004"],
    "device_admin": ["T1626"],
    "crypto_misuse": ["T1573.001"],
    "reflection_abuse": ["T1027.004", "T1127.001"],
    "native_code": ["T1127.001"],
    "network_exfil": ["T1041", "T1573.001"],
    "cert_pinning_bypass": ["T1573.001"],
    "file_exfiltration": ["T1005", "T1041"],
    "ipc_abuse": ["T1417"],
    "runtime_exec": ["T1059.004"],
    "cleartext": ["T1040"],
    "debuggable": ["T1562.001"],
    "backup_allowed": ["T1005"],
}


class RiskAgent(BaseAgent[RiskAnalysis]):
    """Computes explainable risk score from all agent findings."""

    def __init__(self, llm_client: Any = None):
        config = AgentConfig(
            name="risk_agent",
            model="claude-3-5-sonnet-20241022",
            temperature=0.1,
            max_tokens=4096,
            output_schema=RiskAnalysis,
            system_prompt=self._get_system_prompt(),
        )
        super().__init__(config, llm_client)

    def _get_system_prompt(self) -> str:
        return """You are a senior risk analyst specializing in Android malware risk scoring.
Your task is to compute an explainable risk score (0-100) from all agent findings.

The score must be:
1. Deterministic and reproducible (no LLM randomness in the math)
2. Evidence-based with clear factor breakdown
3. Mapped to MITRE ATT&CK and OWASP Mobile
4. Categorized (banking_trojan, spyware, ransomware, adware, etc.)

Weighted factors:
- Manifest/security config: 10%
- Permissions: 15%
- Code anomalies: 20%
- Dangerous API usage: 15%
- Network indicators: 15%
- Threat intelligence: 15%
- Dynamic behavior: 10% (when available)

Output must conform to RiskAnalysis schema with full breakdown."""


    def build_prompt(self, evidence: dict[str, Any], context: dict[str, Any]) -> str:
        # Collect all findings from previous agents
        all_findings = []
        agent_outputs = {}

        for agent_name in ["manifest_agent", "permission_agent", "code_agent", "api_agent", "network_agent", "threat_intel_agent"]:
            findings_key = f"{agent_name}_findings"
            output_key = f"{agent_name}_output"
            if findings_key in context:
                all_findings.extend(context[findings_key])
                agent_outputs[agent_name] = context.get(output_key, {})

        # Also include any findings directly in evidence
        if "findings" in evidence:
            all_findings.extend(evidence["findings"])

        # Compute deterministic score first
        deterministic_result = compute_deterministic_risk(all_findings, agent_outputs)

        prompt = f"""Compute final risk score based on all agent findings.

=== DETERMINISTIC BASELINE SCORE ===
Score: {deterministic_result['score']}
Tier: {deterministic_result['tier']}
Confidence: {deterministic_result['confidence']}

=== FACTOR BREAKDOWN ===
{json.dumps(deterministic_result['breakdown'], indent=2)}

=== ALL FINDINGS ({len(all_findings)} total) ===
{json.dumps([{{
    "id": f.id,
    "type": f.type,
    "severity": f.severity.value if hasattr(f.severity, 'value') else f.severity,
    "confidence": f.confidence.value if hasattr(f.confidence, 'value') else f.confidence,
    "title": f.title,
    "mitre": f.mitre_techniques,
    "owasp": f.owasp_mobile
}} for f in all_findings], indent=2)}

=== AGENT OUTPUTS SUMMARY ===
{json.dumps({k: v.get('summary', {}) if isinstance(v, dict) else {} for k, v in agent_outputs.items()}, indent=2)}

=== RISK WEIGHTS ===
{json.dumps(RISK_WEIGHTS, indent=2)}

Review the deterministic baseline and adjust if LLM reasoning adds context (e.g., novel combinations, 
campaign attribution). Provide final RiskAnalysis with:
1. Final score (0-100) and tier
2. Complete breakdown with RiskFactor entries
3. Category classification
4. MITRE/OWASP mappings
5. Risk narrative
6. Recommended actions

Output complete RiskAnalysis object."""
        return prompt

    def parse_output(self, raw_output: str) -> RiskAnalysis:
        try:
            data = json.loads(raw_output)
        except json.JSONDecodeError:
            import re
            match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', raw_output, re.DOTALL)
            if match:
                data = json.loads(match.group(1))
            else:
                raise ValueError("Could not parse agent output as JSON")

        return RiskAnalysis(**data)

    def extract_findings(self, output: RiskAnalysis) -> list[Finding]:
        return []


def compute_deterministic_risk(findings: list[Finding], agent_outputs: dict[str, Any]) -> dict[str, Any]:
    """Compute deterministic risk score from findings."""
    
    # Group findings by category
    categories = {
        "static_manifest": [],
        "static_permissions": [],
        "static_code": [],
        "static_api": [],
        "static_network": [],
        "threat_intel": [],
    }
    
    for f in findings:
        f_type = f.type if hasattr(f, 'type') else f.get('type', '')
        severity = f.severity if hasattr(f, 'severity') else f.get('severity', 'info')
        confidence = f.confidence if hasattr(f, 'confidence') else f.get('confidence', 'medium')
        
        # Map finding types to categories
        if f_type in ('exported_component', 'debuggable', 'backup_allowed', 'cleartext', 'certificate'):
            categories["static_manifest"].append((f, severity, confidence))
        elif f_type in ('permission', 'permission_risk'):
            categories["static_permissions"].append((f, severity, confidence))
        elif f_type in ('control_flow', 'obfuscation', 'anti_analysis'):
            categories["static_code"].append((f, severity, confidence))
        elif f_type in ('dangerous_api', 'api_usage', 'reflection', 'native_code'):
            categories["static_api"].append((f, severity, confidence))
        elif f_type in ('network', 'c2', 'data_exfil', 'suspicious_domain', 'pinning_bypass'):
            categories["static_network"].append((f, severity, confidence))
        elif f_type in ('threat_intel', 'ioc_match', 'family_attribution', 'actor_attribution'):
            categories["threat_intel"].append((f, severity, confidence))
    
    # Compute weighted score per category
    breakdown = []
    total_score = 0.0
    
    for category, cat_findings in categories.items():
        weight = RISK_WEIGHTS.get(category, 0)
        if not cat_findings:
            cat_score = 0.0
        else:
            # Weight by severity * confidence
            severity_scores = {
                'critical': 100, 'high': 75, 'medium': 50, 'low': 25, 'info': 10,
                Severity.critical: 100, Severity.high: 75, Severity.medium: 50, Severity.low: 25, Severity.info: 10,
            }
            confidence_scores = {
                'very_high': 1.0, 'high': 0.85, 'medium': 0.6, 'low': 0.3,
                Confidence.very_high: 1.0, Confidence.high: 0.85, Confidence.medium: 0.6, Confidence.low: 0.3,
            }
            
            scores = []
            for f, sev, conf in cat_findings:
                sev_score = severity_scores.get(sev, 10)
                conf_score = confidence_scores.get(conf, 0.5)
                scores.append(sev_score * conf_score)
            
            # Use max score in category (most significant finding)
            cat_score = max(scores) if scores else 0
        
        weighted = cat_score * weight
        total_score += weighted
        
        breakdown.append(RiskFactor(
            factor_id=category,
            name=category.replace("_", " ").title(),
            category=category,
            weight=weight,
            raw_score=cat_score,
            weighted_contribution=weighted,
            evidence_refs=[],
            description=f"Category score: {cat_score:.1f}, Weight: {weight}",
            mitre_techniques=[],
            owasp_categories=[],
        ))
    
    # Cap at 100
    final_score = min(100.0, total_score)
    tier = RiskTier.from_score(final_score)
    
    # Confidence based on number of high-severity findings
    high_sev_count = sum(1 for f in findings 
                         if (f.severity if hasattr(f, 'severity') else f.get('severity')) in (Severity.high, Severity.critical, 'high', 'critical'))
    confidence = min(1.0, 0.5 + high_sev_count * 0.1)
    
    # Determine primary category
    primary_category = determine_category(findings, agent_outputs)
    
    return {
        "score": final_score,
        "tier": tier.value,
        "confidence": confidence,
        "breakdown": [b.model_dump() for b in breakdown],
        "primary_category": primary_category,
    }


def determine_category(findings: list[Finding], agent_outputs: dict[str, Any]) -> str:
    """Determine malware category from findings."""
    categories = {
        "banking_trojan": 0,
        "spyware": 0,
        "ransomware": 0,
        "adware": 0,
        "dropper": 0,
        "rootkit": 0,
    }
    
    for f in findings:
        f_type = f.type if hasattr(f, 'type') else f.get('type', '')
        mitre = f.mitre_techniques if hasattr(f, 'mitre_techniques') else f.get('mitre_techniques', [])
        
        if f_type in ('overlay', 'accessibility', 'sms_intercept') or 'T1417' in str(mitre):
            categories["banking_trojan"] += 2
        if f_type in ('permission', 'permission_risk') and any(p in str(f) for p in ['CONTACTS', 'LOCATION', 'RECORD_AUDIO', 'CAMERA']):
            categories["spyware"] += 1
        if f_type in ('device_admin', 'runtime_exec', 'native_code'):
            categories["rootkit"] += 1
        if f_type in ('network', 'c2', 'data_exfil'):
            categories["spyware"] += 1
            categories["banking_trojan"] += 1
        if 'T1486' in str(mitre):  # Data encryption
            categories["ransomware"] += 2
        if f_type in ('ioc_match', 'family_attribution'):
            categories["banking_trojan"] += 3
    
    # Check threat intel for family attribution
    ti_output = agent_outputs.get('threat_intel_agent_output', {})
    if isinstance(ti_output, dict):
        families = ti_output.get('malware_families', [])
        for fam in families:
            fam_name = fam.get('family_name', '').lower()
            if any(b in fam_name for b in ['anubis', 'cerberus', 'eventbot', 'brata', 'teabot', 'flubot', 'xenomorph', 'hook', 'medusa', 'sharkbot']):
                categories["banking_trojan"] += 5
    
    return max(categories, key=categories.get) if max(categories.values()) > 0 else "unknown"