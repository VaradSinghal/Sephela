"""Schemas for Threat Intelligence Agent analysis output."""

from __future__ import annotations

from typing import Any
from pydantic import BaseModel, Field

from ai.schemas.base import Finding, Severity, Confidence, EvidenceRef


class MalwareFamily(BaseModel):
    """Malware family attribution."""
    family_name: str
    aliases: list[str] = Field(default_factory=list)
    confidence: Confidence
    description: str = ""
    mitre_techniques: list[str] = Field(default_factory=list)
    target_sectors: list[str] = Field(default_factory=list)
    target_regions: list[str] = Field(default_factory=list)
    first_seen: str | None = None
    last_seen: str | None = None


class IOCMatch(BaseModel):
    """Indicator of Compromise match."""
    indicator: str
    indicator_type: str = Field(..., pattern="^(hash|domain|ip|url|mutex|registry|file_path|certificate)$")
    source: str
    confidence: Confidence
    severity: Severity
    tags: list[str] = Field(default_factory=list)
    malware_families: list[str] = Field(default_factory=list)
    first_reported: str | None = None
    last_reported: str | None = None
    context: dict[str, Any] = Field(default_factory=dict)


class ThreatActor(BaseModel):
    """Attributed threat actor."""
    name: str
    aliases: list[str] = Field(default_factory=list)
    confidence: Confidence
    motivation: str = Field(..., pattern="^(financial|espionage|hacktivism|destruction|unknown)$")
    sophistication: str = Field(..., pattern="^(low|medium|high|advanced)$")
    target_sectors: list[str] = Field(default_factory=list)
    target_regions: list[str] = Field(default_factory=list)
    known_tools: list[str] = Field(default_factory=list)
    mitre_groups: list[str] = Field(default_factory=list)


class TIConnection(Finding):
    """Threat intelligence connection finding."""
    connection_type: str = Field(..., pattern="^(ioc_match|family_attribution|actor_attribution|campaign_link|infrastructure_overlap)$")
    ioc_matches: list[IOCMatch] = Field(default_factory=list)
    malware_families: list[MalwareFamily] = Field(default_factory=list)
    threat_actors: list[ThreatActor] = Field(default_factory=list)
    campaign_ids: list[str] = Field(default_factory=list)
    confidence: Confidence
    description: str = ""


class ThreatIntelAnalysis(BaseModel):
    """Complete threat intelligence analysis output."""
    # IOC matches
    hash_matches: list[IOCMatch] = Field(default_factory=list)
    domain_matches: list[IOCMatch] = Field(default_factory=list)
    ip_matches: list[IOCMatch] = Field(default_factory=list)
    url_matches: list[IOCMatch] = Field(default_factory=list)
    cert_matches: list[IOCMatch] = Field(default_factory=list)
    
    # Attribution
    malware_families: list[MalwareFamily] = Field(default_factory=list)
    threat_actors: list[ThreatActor] = Field(default_factory=list)
    campaigns: list[str] = Field(default_factory=list)
    
    # Connections
    connections: list[TiConnection] = Field(default_factory=list)
    
    # All findings
    findings: list[Finding] = Field(default_factory=list)
    
    # Summary
    total_ioc_matches: int = 0
    malicious_hash_matches: int = 0
    malicious_domain_matches: int = 0
    malicious_ip_matches: int = 0
    family_attributions: int = 0
    actor_attributions: int = 0
    critical_findings: int = 0
    high_findings: int = 0
    medium_findings: int = 0
    low_findings: int = 0

    def model_post_init(self, __context: Any) -> None:
        """Compute summary counts."""
        self.total_ioc_matches = (
            len(self.hash_matches) + len(self.domain_matches) + 
            len(self.ip_matches) + len(self.url_matches) + len(self.cert_matches)
        )
        self.malicious_hash_matches = sum(1 for m in self.hash_matches if m.severity in (Severity.high, Severity.critical))
        self.malicious_domain_matches = sum(1 for m in self.domain_matches if m.severity in (Severity.high, Severity.critical))
        self.malicious_ip_matches = sum(1 for m in self.ip_matches if m.severity in (Severity.high, Severity.critical))
        
        self.family_attributions = len(self.malware_families)
        self.actor_attributions = len(self.threat_actors)
        
        all_findings = list(self.findings)
        for f in all_findings:
            if f.severity == Severity.critical:
                self.critical_findings += 1
            elif f.severity == Severity.high:
                self.high_findings += 1
            elif f.severity == Severity.medium:
                self.medium_findings += 1
            elif f.severity == Severity.low:
                self.low_findings += 1