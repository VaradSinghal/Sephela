"""Schemas for Network Agent analysis output."""

from __future__ import annotations

from typing import Any
from pydantic import BaseModel, Field, HttpUrl

from ai.schemas.base import Finding, Severity, Confidence, EvidenceRef


class NetworkConnection(BaseModel):
    """Observed or declared network connection."""
    host: str
    port: int | None = None
    protocol: str = Field(..., pattern="^(http|https|tcp|udp|ws|wss)$")
    source: str = Field(..., pattern="^(manifest|string|code|dynamic|certificate)$")
    context: str = ""  # e.g., "Retrofit baseUrl", "Firebase config", "C2 domain"
    is_suspicious: bool = False
    suspicion_reasons: list[str] = Field(default_factory=list)


class DomainIntel(BaseModel):
    """Domain intelligence from TI."""
    domain: str
    is_malicious: bool = False
    categories: list[str] = Field(default_factory=list)
    reputation_score: float | None = Field(None, ge=0.0, le=1.0)
    first_seen: str | None = None
    last_seen: str | None = None
    registrar: str | None = None
    country: str | None = None
    is_dga: bool = False
    is_newly_registered: bool = False
    related_malware_families: list[str] = Field(default_factory=list)


class IPIntel(BaseModel):
    """IP intelligence from TI."""
    ip: str
    is_malicious: bool = False
    categories: list[str] = Field(default_factory=list)
    reputation_score: float | None = Field(None, ge=0.0, le=1.0)
    asn: str | None = None
    asn_name: str | None = None
    country: str | None = None
    is_tor: bool = False
    is_vpn: bool = False
    is_hosting: bool = False
    related_malware_families: list[str] = Field(default_factory=list)


class CertificateInfo(BaseModel):
    """SSL/TLS certificate details."""
    subject: str
    issuer: str
    serial_number: str
    sha256: str
    not_before: str
    not_after: str
    is_self_signed: bool = False
    is_expired: bool = False
    pinning_detected: bool = False
    pin_sha256: list[str] = Field(default_factory=list)


class NetworkFinding(Finding):
    """Network-specific finding."""
    finding_type: str = Field(..., pattern="^(c2|data_exfil|insecure_config|suspicious_domain|pinning_bypass|cleartext|cert_pinning)$")
    indicator: str
    indicator_type: str = Field(..., pattern="^(domain|ip|url|certificate)$")
    ti_context: DomainIntel | IPIntel | CertificateInfo | None = None
    protocol: str | None = None
    port: int | None = None


class NetworkAnalysis(BaseModel):
    """Complete network analysis output."""
    # Extracted indicators
    domains: list[str] = Field(default_factory=list)
    ips: list[str] = Field(default_factory=list)
    urls: list[HttpUrl] = Field(default_factory=list)
    certificates: list[CertificateInfo] = Field(default_factory=list)
    
    # Connections
    connections: list[NetworkConnection] = Field(default_factory=list)
    
    # TI enrichment
    domain_intel: list[DomainIntel] = Field(default_factory=list)
    ip_intel: list[IPIntel] = Field(default_factory=list)
    
    # Findings
    findings: list[NetworkFinding] = Field(default_factory=list)
    
    # Configuration
    network_security_config: str | None = None
    cleartext_permitted: bool = False
    pinning_implemented: bool = False
    pinning_bypass_detected: bool = False
    
    # Summary
    malicious_domain_count: int = 0
    malicious_ip_count: int = 0
    suspicious_connection_count: int = 0
    critical_findings: int = 0
    high_findings: int = 0
    medium_findings: int = 0
    low_findings: int = 0

    def model_post_init(self, __context: Any) -> None:
        """Compute summary counts."""
        self.malicious_domain_count = sum(1 for d in self.domain_intel if d.is_malicious)
        self.malicious_ip_count = sum(1 for i in self.ip_intel if i.is_malicious)
        self.suspicious_connection_count = sum(1 for c in self.connections if c.is_suspicious)
        
        for f in self.findings:
            if f.severity == Severity.critical:
                self.critical_findings += 1
            elif f.severity == Severity.high:
                self.high_findings += 1
            elif f.severity == Severity.medium:
                self.medium_findings += 1
            elif f.severity == Severity.low:
                self.low_findings += 1