"""Network Agent - Analyzes network indicators, connections, and TLS configuration."""

from __future__ import annotations

import json
import re
from typing import Any

from pydantic import BaseModel

from ai.schemas.base import Finding, Severity, Confidence, EvidenceRef
from ai.schemas.network import NetworkAnalysis, NetworkConnection, DomainIntel, IPIntel, CertificateInfo, NetworkFinding
from ai.agents.base import BaseAgent, AgentConfig, AgentResult


SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".work", ".date", ".loan",
    ".download", ".racing", ".win", ".bid", ".trade", ".party", ".science", ".stream",
}

KNOWN_C2_PATTERNS = [
    r".*\.ddns\.net$",
    r".*\.no-ip\.(com|org|biz)$",
    r".*\.dyndns\.(org|com)$",
    r".*\.hopto\.org$",
    r".*\.servehttp\.com$",
    r".*\.zapto\.org$",
    r"[a-z0-9]{20,}\.com$",
    r"[a-z0-9]{15,}\.(tk|ml|ga|cf|gq)$",
]

BANKING_TARGET_KEYWORDS = [
    "bank", "chase", "wellsfargo", "citi", "bankofamerica", "capitalone",
    "paypal", "venmo", "cashapp", "zelle", "coinbase", "binance",
    "crypto", "wallet", "ledger", "trezor",
]


class NetworkAgent(BaseAgent[NetworkAnalysis]):
    """Analyzes network IOCs, connections, certificates, and TLS configuration."""

    def __init__(self, llm_client: Any = None):
        config = AgentConfig(
            name="network_agent",
            model="claude-3-5-sonnet-20241022",
            temperature=0.1,
            max_tokens=4096,
            output_schema=NetworkAnalysis,
            system_prompt=self._get_system_prompt(),
        )
        super().__init__(config, llm_client)

    def _get_system_prompt(self) -> str:
        return """You are a senior network security analyst specializing in Android malware traffic analysis.
Your task is to analyze network indicators extracted from an APK and identify:

1. Command & Control (C2) infrastructure
2. Data exfiltration endpoints
3. Suspicious domains/IPs (newly registered, DGA, known bad)
4. Certificate anomalies (self-signed, pinning bypass, expired)
5. Cleartext traffic and network security config issues
6. Certificate pinning implementation and bypasses
7. Banking/financial target indicators

For each finding, provide:
- Clear severity (critical/high/medium/low/info)
- Confidence level
- MITRE ATT&CK technique mappings (T1071, T1573, T1041, etc.)
- OWASP Mobile Top 10 mappings (M3, M5, M9)
- Evidence reference to the static/network extractor output
- Threat intelligence context if available

Output must conform to the NetworkAnalysis schema."""

    def build_prompt(self, evidence: dict[str, Any], context: dict[str, Any]) -> str:
        static_evidence = evidence.get("static_evidence", {})
        network_evidence = static_evidence.get("network", {})
        strings_evidence = static_evidence.get("strings", {})
        cert_evidence = static_evidence.get("certificate", {})
        manifest_evidence = static_evidence.get("manifest", {})

        domains = network_evidence.get("domains", [])
        ips = network_evidence.get("ips", [])
        urls = network_evidence.get("urls", [])
        certs = cert_evidence.get("certificates", [])
        net_config = manifest_evidence.get("network_security_config")
        cleartext = manifest_evidence.get("uses_cleartext_traffic", False)

        prompt = f"""Analyze the following network indicators:

=== EXTRACTED DOMAINS ({len(domains)}) ===
{json.dumps(domains[:100], indent=2)}

=== EXTRACTED IPs ({len(ips)}) ===
{json.dumps(ips[:50], indent=2)}

=== EXTRACTED URLs ({len(urls)}) ===
{json.dumps(urls[:100], indent=2)}

=== CERTIFICATES ({len(certs)}) ===
{json.dumps(certs, indent=2)}

=== NETWORK SECURITY CONFIG ===
{json.dumps(net_config, indent=2) if net_config else "Not configured"}

=== CLEARTEXT TRAFFIC PERMITTED === {cleartext}

=== SUSPICIOUS STRINGS (network-related) ===
{json.dumps([s for s in strings_evidence.get("suspicious", []) if any(kw in s.lower() for kw in ["http", "tcp", "udp", "socket", "connect", "host", "port", "c2", "cmd", "server", "api", "endpoint"])], indent=2)}

=== SUSPICIOUS TLDs REFERENCE ===
{json.dumps(list(SUSPICIOUS_TLDS))}

=== KNOWN C2 PATTERNS ===
{json.dumps(KNOWN_C2_PATTERNS)}

=== BANKING TARGET KEYWORDS ===
{json.dumps(BANKING_TARGET_KEYWORDS)}

Analyze and output a complete NetworkAnalysis object with:
1. NetworkConnection for each domain/IP/URL with context
2. DomainIntel and IPIntel for TI enrichment (mark suspicious ones)
3. CertificateInfo for each certificate with pinning analysis
4. NetworkFinding for each security issue
5. Summary counts for malicious/suspicious indicators"""
        return prompt

    def parse_output(self, raw_output: str) -> NetworkAnalysis:
        try:
            data = json.loads(raw_output)
        except json.JSONDecodeError:
            match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', raw_output, re.DOTALL)
            if match:
                data = json.loads(match.group(1))
            else:
                raise ValueError("Could not parse agent output as JSON")

        return NetworkAnalysis(**data)

    def extract_findings(self, output: NetworkAnalysis) -> list[Finding]:
        return output.findings


def analyze_network_deterministic(evidence: dict[str, Any], ti_context: dict[str, Any] = None) -> NetworkAnalysis:
    """Deterministic network analysis without LLM."""
    network_evidence = evidence.get("static_evidence", {}).get("network", {})
    cert_evidence = evidence.get("static_evidence", {}).get("certificate", {})
    manifest_evidence = evidence.get("static_evidence", {}).get("manifest", {})

    domains = network_evidence.get("domains", [])
    ips = network_evidence.get("ips", [])
    urls = network_evidence.get("urls", [])
    certs = cert_evidence.get("certificates", [])

    connections = []
    domain_intel = []
    ip_intel = []
    certificate_info = []
    findings = []

    # Analyze domains
    for domain in domains:
        is_suspicious = False
        reasons = []

        tld = "." + domain.split(".")[-1] if "." in domain else ""
        if tld in SUSPICIOUS_TLDS:
            is_suspicious = True
            reasons.append(f"Suspicious TLD: {tld}")

        for pattern in KNOWN_C2_PATTERNS:
            if re.match(pattern, domain):
                is_suspicious = True
                reasons.append(f"Matches C2 pattern: {pattern}")
                break

        for kw in BANKING_TARGET_KEYWORDS:
            if kw in domain.lower():
                is_suspicious = True
                reasons.append(f"Banking target keyword: {kw}")
                break

        connections.append(NetworkConnection(
            host=domain,
            protocol="https",
            source="string",
            context="Extracted from strings/network analysis",
            is_suspicious=is_suspicious,
            suspicion_reasons=reasons,
        ))

        if ti_context and domain in ti_context.get("domains", {}):
            ti = ti_context["domains"][domain]
            domain_intel.append(DomainIntel(
                domain=domain,
                is_malicious=ti.get("malicious", False),
                categories=ti.get("categories", []),
                reputation_score=ti.get("reputation"),
                first_seen=ti.get("first_seen"),
                last_seen=ti.get("last_seen"),
                registrar=ti.get("registrar"),
                country=ti.get("country"),
                is_dga=ti.get("is_dga", False),
                is_newly_registered=ti.get("newly_registered", False),
                related_malware_families=ti.get("families", []),
            ))
            if ti.get("malicious"):
                findings.append(NetworkFinding(
                    id=f"domain_malicious:{domain}",
                    type="network",
                    severity=Severity.critical,
                    confidence=Confidence.very_high,
                    title=f"Malicious domain: {domain}",
                    description=f"Domain flagged as malicious by threat intelligence: {ti.get('categories', [])}",
                    evidence_refs=[EvidenceRef(extractor="network", path="domains")],
                    finding_type="suspicious_domain",
                    indicator=domain,
                    indicator_type="domain",
                    ti_context=domain_intel[-1],
                    mitre_techniques=["T1071.001"],
                    owasp_mobile=["M3"],
                ))

    # Analyze IPs
    for ip in ips:
        connections.append(NetworkConnection(
            host=ip,
            protocol="tcp",
            source="string",
            context="Extracted IP address",
            is_suspicious=not ip.startswith(("10.", "192.168.", "172.16.", "127.")),
            suspicion_reasons=["Public IP address"] if not ip.startswith(("10.", "192.168.", "172.16.", "127.")) else [],
        ))

    # Analyze certificates
    for cert in certs:
        cert_info = CertificateInfo(
            subject=cert.get("subject", ""),
            issuer=cert.get("issuer", ""),
            serial_number=cert.get("serial", ""),
            sha256=cert.get("sha256", ""),
            not_before=cert.get("not_before", ""),
            not_after=cert.get("not_after", ""),
            is_self_signed=cert.get("self_signed", False),
            is_expired=cert.get("expired", False),
            pinning_detected=cert.get("pinning", False),
            pin_sha256=cert.get("pins", []),
        )
        certificate_info.append(cert_info)

        if cert_info.is_self_signed:
            findings.append(NetworkFinding(
                id=f"cert_self_signed:{cert_info.sha256[:16]}",
                type="network",
                severity=Severity.high,
                confidence=Confidence.very_high,
                title="Self-signed certificate",
                description="Certificate is self-signed - potential MITM or custom CA",
                evidence_refs=[EvidenceRef(extractor="certificate", path="certificates")],
                finding_type="cert_pinning",
                indicator=cert_info.sha256,
                indicator_type="certificate",
                ti_context=cert_info,
                mitre_techniques=["T1573.002"],
                owasp_mobile=["M5"],
            ))

    # Network security config
    net_config = manifest_evidence.get("network_security_config")
    cleartext = manifest_evidence.get("uses_cleartext_traffic", False)
    pinning = bool(net_config and "pin-set" in str(net_config))

    if cleartext:
        findings.append(NetworkFinding(
            id="cleartext_permitted",
            type="network",
            severity=Severity.medium,
            confidence=Confidence.very_high,
            title="Cleartext traffic permitted",
            description="android:usesCleartextTraffic=true or network security config allows cleartext",
            evidence_refs=[EvidenceRef(extractor="manifest", path="uses_cleartext_traffic")],
            finding_type="cleartext",
            indicator="cleartext",
            indicator_type="configuration",
            mitre_techniques=["T1040"],
            owasp_mobile=["M3", "M5"],
        ))

    return NetworkAnalysis(
        domains=domains,
        ips=ips,
        urls=urls,
        certificates=certificate_info,
        connections=connections,
        domain_intel=domain_intel,
        ip_intel=ip_intel,
        findings=findings,
        network_security_config=str(net_config) if net_config else None,
        cleartext_permitted=cleartext,
        pinning_implemented=pinning,
        pinning_bypass_detected=False,
    )