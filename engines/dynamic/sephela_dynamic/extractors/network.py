"""Network trace extractor — parses network activity from sandbox captures.

Reads ``network.json`` (a structured export from Suricata EVE or a PCAP-to-JSON
converter) and extracts:
- Contacted IP addresses and domains
- DNS resolutions
- Cleartext HTTP traffic (high-risk for credential leaks)
- TLS handshake metadata (SNI, JA3, certificate info)
- Known-bad port usage (IRC, Tor, non-standard ports)

Security note: Network payloads may contain exploit code or injected strings.
We extract metadata only and never interpret body content as executable.
"""

from __future__ import annotations

import json
from typing import Any

from sephela_dynamic.base import ArtifactsContext, DynamicExtractor, ExtractorResult
from sephela_dynamic.envelope import (
    Finding,
    FindingType,
    Mappings,
    Provenance,
    Severity,
)
from sephela_dynamic.schemas import NetworkTrace

# Ports commonly used by malware C2
_SUSPICIOUS_PORTS: dict[int, str] = {
    4444: "Meterpreter default",
    6667: "IRC (C2 channel)",
    6697: "IRC over TLS",
    8080: "HTTP alt (common C2)",
    8443: "HTTPS alt",
    9050: "Tor SOCKS",
    9051: "Tor control",
    31337: "Back Orifice / elite",
}

# RFC 5737 / RFC 3849 documentation ranges (should never appear in real traffic
# from a sandbox — their presence means C2 avoidance or test artefacts)
_BOGON_PREFIXES = ("0.", "10.", "127.", "169.254.", "172.16.", "192.0.2.", "198.51.100.", "203.0.113.")


class NetworkExtractor(DynamicExtractor):
    """Parse network traces into structured findings."""

    name = "network"
    required_artifacts = ["network.json"]

    def extract(self, ctx: ArtifactsContext) -> ExtractorResult:
        """Parse network.json and emit findings for suspicious activity.

        Args:
            ctx: Artifacts context with the sandbox output directory.

        Returns:
            Structured evidence with network statistics and findings.
        """
        raw = ctx.read_artifact("network.json")
        if raw is None:
            return ExtractorResult(
                evidence={"error": "network.json not found"},
            )

        data = json.loads(raw)
        trace = NetworkTrace.model_validate(data)

        findings: list[Finding] = []

        # --- Unique destinations ---
        dst_ips: set[str] = set()
        dst_domains: set[str] = set()
        for conn in trace.connections:
            dst_ips.add(conn.dst_ip)
            if conn.dst_hostname:
                dst_domains.add(conn.dst_hostname)

        for dns in trace.dns_queries:
            dst_domains.add(dns.query)
            dst_ips.update(dns.response_ips)

        for tls in trace.tls_handshakes:
            dst_domains.add(tls.server_name)

        # --- Cleartext HTTP ---
        cleartext_requests = [r for r in trace.http_requests if r.is_cleartext]
        if cleartext_requests:
            hosts = {r.host for r in cleartext_requests}
            findings.append(Finding(
                id=f"dyn_net_cleartext_{len(cleartext_requests)}",
                type=FindingType.network,
                severity=Severity.high,
                confidence=0.90,
                detail=(
                    f"Cleartext HTTP traffic detected to {len(hosts)} host(s): "
                    f"{', '.join(sorted(hosts)[:5])}. Credentials and data may be "
                    f"exposed in transit."
                ),
                provenance=Provenance(extractor=self.name),
                mappings=Mappings(
                    mitre=["T1071.001"],  # Web Protocols
                    owasp_mobile=["M3"],  # Insecure Communication
                ),
            ))

        # --- Suspicious ports ---
        for conn in trace.connections:
            port_desc = _SUSPICIOUS_PORTS.get(conn.dst_port)
            if port_desc:
                findings.append(Finding(
                    id=f"dyn_net_port_{conn.dst_port}_{conn.dst_ip}",
                    type=FindingType.network,
                    severity=Severity.high,
                    confidence=0.75,
                    detail=(
                        f"Connection to {conn.dst_ip}:{conn.dst_port} — "
                        f"commonly associated with {port_desc}."
                    ),
                    provenance=Provenance(
                        extractor=self.name,
                        timestamp_ms=conn.timestamp_ms,
                    ),
                    mappings=Mappings(mitre=["T1571"]),  # Non-Standard Port
                ))

        # --- High volume (data exfiltration indicator) ---
        if trace.total_bytes_sent > 1_000_000:
            findings.append(Finding(
                id="dyn_net_high_egress",
                type=FindingType.network,
                severity=Severity.high,
                confidence=0.70,
                detail=(
                    f"High outbound data volume: {trace.total_bytes_sent:,} bytes sent. "
                    f"Potential data exfiltration."
                ),
                provenance=Provenance(extractor=self.name),
                mappings=Mappings(mitre=["T1041"]),  # Exfiltration Over C2
            ))

        # --- Multiple unique external IPs (C2 diversity) ---
        external_ips = {ip for ip in dst_ips if not any(ip.startswith(p) for p in _BOGON_PREFIXES)}
        if len(external_ips) >= 5:
            findings.append(Finding(
                id=f"dyn_net_multi_c2_{len(external_ips)}",
                type=FindingType.network,
                severity=Severity.medium,
                confidence=0.65,
                detail=(
                    f"Contacted {len(external_ips)} unique external IPs. "
                    f"Multiple C2 endpoints or DGA behaviour possible."
                ),
                provenance=Provenance(extractor=self.name),
                mappings=Mappings(mitre=["T1568"]),  # Dynamic Resolution
            ))

        # --- TLS certificate anomalies ---
        for tls in trace.tls_handshakes:
            if tls.certificate_issuer and tls.certificate_issuer == tls.certificate_subject:
                findings.append(Finding(
                    id=f"dyn_net_selfsigned_{tls.server_name}",
                    type=FindingType.network,
                    severity=Severity.medium,
                    confidence=0.70,
                    detail=(
                        f"Self-signed TLS certificate for {tls.server_name}. "
                        f"Common in C2 infrastructure."
                    ),
                    provenance=Provenance(
                        extractor=self.name,
                        timestamp_ms=tls.timestamp_ms,
                    ),
                    mappings=Mappings(mitre=["T1587.003"]),  # Digital Certificates
                ))

        evidence: dict[str, object] = {
            "unique_dst_ips": sorted(dst_ips),
            "unique_dst_domains": sorted(dst_domains),
            "external_ips": sorted(external_ips),
            "total_connections": len(trace.connections),
            "total_dns_queries": len(trace.dns_queries),
            "total_http_requests": len(trace.http_requests),
            "cleartext_http_count": len(cleartext_requests),
            "total_bytes_sent": trace.total_bytes_sent,
            "total_bytes_recv": trace.total_bytes_recv,
            "tls_handshakes": len(trace.tls_handshakes),
            "suspicious_ports_contacted": [
                {"ip": c.dst_ip, "port": c.dst_port, "desc": _SUSPICIOUS_PORTS[c.dst_port]}
                for c in trace.connections if c.dst_port in _SUSPICIOUS_PORTS
            ],
        }

        return ExtractorResult(evidence=evidence, findings=findings)
