"""Threat Intelligence Agent - Enriches findings with external threat intelligence."""

from __future__ import annotations

import json
from typing import Any

from pydantic import BaseModel

from ai.schemas.base import Finding, Severity, Confidence, EvidenceRef
from ai.schemas.threat_intel import ThreatIntelAnalysis, MalwareFamily, IOCMatch, ThreatActor, TiConnection
from ai.agents.base import BaseAgent, AgentConfig, AgentResult


TI_SOURCES = [
    "VirusTotal",
    "AlienVault OTX",
    "AbuseIPDB",
    "URLhaus",
    "MalwareBazaar",
    "Hybrid Analysis",
    "MITRE ATT&CK",
    "MISP",
]

MALWARE_FAMILIES_BANKING = {
    "Anubis": {"mitre": ["T1417", "T1636.004", "T1582"], "overlay": True, "accessibility": True, "sms": True},
    "Cerberus": {"mitre": ["T1417", "T1636.004"], "overlay": True, "accessibility": True, "sms": True},
    "EventBot": {"mitre": ["T1417", "T1636.004", "T1582"], "overlay": True, "accessibility": True, "sms": True},
    "BRATA": {"mitre": ["T1417", "T1127"], "overlay": True, "accessibility": True, "screen_streaming": True},
    "TeaBot": {"mitre": ["T1417", "T1636.004"], "overlay": True, "accessibility": True, "sms": True},
    "Flubot": {"mitre": ["T1636.004", "T1582"], "sms": True, "spreader": True},
    "Xenomorph": {"mitre": ["T1417", "T1636.004"], "overlay": True, "accessibility": True, "sms": True, "automated_transfer": True},
    "Hook": {"mitre": ["T1417", "T1636.004"], "overlay": True, "accessibility": True, "sms": True, "vnc": True},
    "Medusa": {"mitre": ["T1417", "T1636.004"], "overlay": True, "accessibility": True, "sms": True, "keylogger": True},
    "SharkBot": {"mitre": ["T1417", "T1582"], "overlay": True, "ats": True, "auto_transfer": True},
}


class ThreatIntelAgent(BaseAgent[ThreatIntelAnalysis]):
    """Enriches analysis with threat intelligence from multiple sources."""

    def __init__(self, llm_client: Any = None):
        config = AgentConfig(
            name="threat_intel_agent",
            model="claude-3-5-sonnet-20241022",
            temperature=0.1,
            max_tokens=4096,
            output_schema=ThreatIntelAnalysis,
            system_prompt=self._get_system_prompt(),
        )
        super().__init__(config, llm_client)

    def _get_system_prompt(self) -> str:
        return """You are a senior threat intelligence analyst specializing in Android malware.
Your task is to correlate extracted IOCs (hashes, domains, IPs, URLs, certificates) with threat intelligence
and attribute findings to known malware families, campaigns, and threat actors.

For each IOC match, provide:
- Source of intelligence
- Confidence and severity
- Malware family attribution with MITRE techniques
- Threat actor attribution if possible
- Campaign links
- Context (first seen, last seen, targeting)

Focus on banking trojans and financial malware.
Output must conform to the ThreatIntelAnalysis schema."""

    def build_prompt(self, evidence: dict[str, Any], context: dict[str, Any]) -> str:
        static_evidence = evidence.get("static_evidence", {})
        network_evidence = static_evidence.get("network", {})
        hashes_evidence = static_evidence.get("hashes", {})
        cert_evidence = static_evidence.get("certificate", {})
        manifest_evidence = static_evidence.get("manifest", {})
        code_intel = evidence.get("code_intel", {})

        # Gather all IOCs
        file_hash = hashes_evidence.get("sha256", "")
        domains = network_evidence.get("domains", [])
        ips = network_evidence.get("ips", [])
        urls = network_evidence.get("urls", [])
        certs = cert_evidence.get("certificates", [])
        permissions = static_evidence.get("permissions", {}).get("permissions", [])
        package_name = manifest_evidence.get("package_name", "")

        # Previous agent outputs for correlation
        manifest_findings = context.get("manifest_agent_findings", [])
        permission_findings = context.get("permission_agent_findings", [])
        code_findings = context.get("code_agent_findings", [])
        api_findings = context.get("api_agent_findings", [])
        network_findings = context.get("network_agent_findings", [])

        prompt = f"""Analyze the following IOCs and findings for threat intelligence correlation:

=== FILE HASH ===
SHA256: {file_hash}

=== NETWORK IOCs ===
Domains ({len(domains)}): {json.dumps(domains[:50])}
IPs ({len(ips)}): {json.dumps(ips[:20])}
URLs ({len(urls)}): {json.dumps(urls[:50])}

=== CERTIFICATES ({len(certs)}) ===
{json.dumps(certs, indent=2)}

=== PACKAGE NAME ===
{package_name}

=== PERMISSIONS ({len(permissions)}) ===
{json.dumps(permissions)}

=== PREVIOUS AGENT FINDINGS ===
Manifest: {len(manifest_findings)} findings
Permissions: {len(permission_findings)} findings
Code: {len(code_findings)} findings
API: {len(api_findings)} findings
Network: {len(network_findings)} findings

=== KNOWN BANKING MALWARE FAMILIES ===
{json.dumps(MALWARE_FAMILIES_BANKING, indent=2)}

=== TI SOURCES ===
{json.dumps(TI_SOURCES)}

Correlate IOCs with threat intelligence. Attribute to malware families, threat actors, and campaigns.
Output complete ThreatIntelAnalysis object."""
        return prompt

    def parse_output(self, raw_output: str) -> ThreatIntelAnalysis:
        try:
            data = json.loads(raw_output)
        except json.JSONDecodeError:
            import re
            match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', raw_output, re.DOTALL)
            if match:
                data = json.loads(match.group(1))
            else:
                raise ValueError("Could not parse agent output as JSON")

        return ThreatIntelAnalysis(**data)

    def extract_findings(self, output: ThreatIntelAnalysis) -> list[Finding]:
        return output.findings


def analyze_threat_intel_deterministic(evidence: dict[str, Any], ti_cache: dict[str, Any] = None) -> ThreatIntelAnalysis:
    """Deterministic threat intelligence correlation using cached data."""
    static_evidence = evidence.get("static_evidence", {})
    network_evidence = static_evidence.get("network", {})
    hashes_evidence = static_evidence.get("hashes", {})
    cert_evidence = static_evidence.get("certificate", {})

    file_hash = hashes_evidence.get("sha256", "")
    domains = network_evidence.get("domains", [])
    ips = network_evidence.get("ips", [])
    urls = network_evidence.get("urls", [])
    certs = cert_evidence.get("certificates", [])

    hash_matches = []
    domain_matches = []
    ip_matches = []
    url_matches = []
    cert_matches = []
    malware_families = []
    threat_actors = []
    connections = []
    findings = []

    # Check hash against known malware (mock)
    if ti_cache and file_hash in ti_cache.get("hashes", {}):
        match = ti_cache["hashes"][file_hash]
        hash_matches.append(IOCMatch(
            indicator=file_hash,
            indicator_type="hash",
            source=match.get("source", "MalwareBazaar"),
            confidence=Confidence.very_high,
            severity=Severity.critical,
            tags=match.get("tags", []),
            malware_families=match.get("families", []),
            first_reported=match.get("first_seen"),
            last_reported=match.get("last_seen"),
            context=match,
        ))
        for fam in match.get("families", []):
            if fam in MALWARE_FAMILIES_BANKING:
                mf = MALWARE_FAMILIES_BANKING[fam]
                malware_families.append(MalwareFamily(
                    family_name=fam,
                    aliases=match.get("aliases", []),
                    confidence=Confidence.very_high,
                    description=f"Known banking trojan: {fam}",
                    mitre_techniques=mf["mitre"],
                    target_sectors=["financial"],
                    target_regions=["global"],
                ))
                findings.append(TiConnection(
                    id=f"family:{fam}",
                    type="threat_intel",
                    severity=Severity.critical,
                    confidence=Confidence.very_high,
                    title=f"Malware family attributed: {fam}",
                    description=f"Sample matches known {fam} banking trojan",
                    evidence_refs=[EvidenceRef(extractor="hashes", path="sha256")],
                    connection_type="family_attribution",
                    ioc_matches=hash_matches,
                    malware_families=[malware_families[-1]],
                    confidence=Confidence.very_high,
                    mitre_techniques=mf["mitre"],
                    owasp_mobile=["M1", "M3", "M5"],
                ))

    # Check domains
    for domain in domains:
        if ti_cache and domain in ti_cache.get("domains", {}):
            match = ti_cache["domains"][domain]
            domain_matches.append(IOCMatch(
                indicator=domain,
                indicator_type="domain",
                source=match.get("source", "OTX"),
                confidence=Confidence.high if match.get("malicious") else Confidence.medium,
                severity=Severity.critical if match.get("malicious") else Severity.medium,
                tags=match.get("categories", []),
                malware_families=match.get("families", []),
                first_reported=match.get("first_seen"),
                last_reported=match.get("last_seen"),
                context=match,
            ))

    # Check IPs
    for ip in ips:
        if ti_cache and ip in ti_cache.get("ips", {}):
            match = ti_cache["ips"][ip]
            ip_matches.append(IOCMatch(
                indicator=ip,
                indicator_type="ip",
                source=match.get("source", "AbuseIPDB"),
                confidence=Confidence.high if match.get("malicious") else Confidence.medium,
                severity=Severity.critical if match.get("malicious") else Severity.medium,
                tags=match.get("categories", []),
                malware_families=match.get("families", []),
                first_reported=match.get("first_seen"),
                last_reported=match.get("last_seen"),
                context=match,
            ))

    # Summary
    total_matches = len(hash_matches) + len(domain_matches) + len(ip_matches) + len(url_matches) + len(cert_matches)

    return ThreatIntelAnalysis(
        hash_matches=hash_matches,
        domain_matches=domain_matches,
        ip_matches=ip_matches,
        url_matches=url_matches,
        cert_matches=cert_matches,
        malware_families=malware_families,
        threat_actors=threat_actors,
        connections=connections,
        findings=findings,
        total_ioc_matches=total_matches,
        malicious_hash_matches=len([m for m in hash_matches if m.severity in (Severity.high, Severity.critical)]),
        malicious_domain_matches=len([m for m in domain_matches if m.severity in (Severity.high, Severity.critical)]),
        malicious_ip_matches=len([m for m in ip_matches if m.severity in (Severity.high, Severity.critical)]),
        family_attributions=len(malware_families),
        actor_attributions=len(threat_actors),
    )