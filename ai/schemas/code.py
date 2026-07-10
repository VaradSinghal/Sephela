"""Schemas for Code Agent analysis output."""

from __future__ import annotations

from typing import Any
from pydantic import BaseModel, Field

from ai.schemas.base import Finding, Severity, Confidence, EvidenceRef


class MethodInfo(BaseModel):
    """Decompiled method metadata."""
    class_name: str
    method_name: str
    return_type: str
    parameters: list[str] = Field(default_factory=list)
    access_flags: list[str] = Field(default_factory=list)
    is_constructor: bool = False
    is_native: bool = False
    is_abstract: bool = False
    bytecode_size: int = 0
    cyclomatic_complexity: int = 1


class ClassInfo(BaseModel):
    """Decompiled class metadata."""
    class_name: str
    superclass: str | None = None
    interfaces: list[str] = Field(default_factory=list)
    access_flags: list[str] = Field(default_factory=list)
    is_outer_class: bool = True
    methods: list[MethodInfo] = Field(default_factory=list)
    fields: list[dict[str, Any]] = Field(default_factory=list)
    annotations: list[str] = Field(default_factory=list)


class CallGraphEdge(BaseModel):
    """Single edge in call graph."""
    caller: str
    callee: str
    call_type: str = Field(..., pattern="^(direct|virtual|interface|super|static)$")
    line_number: int | None = None
    confidence: float = Field(1.0, ge=0.0, le=1.0)


class CallGraph(BaseModel):
    """Method call graph."""
    nodes: list[str] = Field(default_factory=list)  # method signatures
    edges: list[CallGraphEdge] = Field(default_factory=list)
    entry_points: list[str] = Field(default_factory=list)
    sinks: list[str] = Field(default_factory=list)


class ControlFlowFinding(Finding):
    """Control flow anomaly finding."""
    method_signature: str
    anomaly_type: str = Field(..., pattern="^(unreachable|infinite_loop|exception_swallowing|dead_code|obfuscated)$")
    snippet: str | None = None
    explanation: str = ""


class APIUsageFinding(Finding):
    """Dangerous API usage finding."""
    api_class: str
    api_method: str
    api_package: str
    call_sites: list[str] = Field(default_factory=list)  # method signatures calling this API
    data_flow: list[str] = Field(default_factory=list)  # tainted variable traces
    is_reflection: bool = False
    is_dynamic_loading: bool = False


class CodeSummary(BaseModel):
    """Token-optimized code summary for LLM consumption."""
    total_classes: int = 0
    total_methods: int = 0
    app_classes: int = 0  # non-framework, non-library
    app_methods: int = 0
    
    # Key structures
    entry_points: list[str] = Field(default_factory=list)  # activities, services, receivers
    network_apis: list[str] = Field(default_factory=list)
    crypto_apis: list[str] = Field(default_factory=list)
    file_io_apis: list[str] = Field(default_factory=list)
    ipc_apis: list[str] = Field(default_factory=list)
    reflection_usage: list[str] = Field(default_factory=list)
    native_libs: list[str] = Field(default_factory=list)
    
    # Suspicious patterns
    string_obfuscation: bool = False
    class_encryption: bool = False
    anti_analysis: list[str] = Field(default_factory=list)
    
    # Banking-specific
    banking_apis: list[str] = Field(default_factory=list)
    overlay_apis: list[str] = Field(default_factory=list)
    accessibility_apis: list[str] = Field(default_factory=list)
    sms_apis: list[str] = Field(default_factory=list)


class CodeAnalysis(BaseModel):
    """Complete code analysis output."""
    # Structural
    classes: list[ClassInfo] = Field(default_factory=list)
    call_graph: CallGraph | None = None
    
    # Findings
    control_flow_findings: list[ControlFlowFinding] = Field(default_factory=list)
    api_usage_findings: list[APIUsageFinding] = Field(default_factory=list)
    
    # Summary for LLM
    summary: CodeSummary = Field(default_factory=CodeSummary)
    
    # All findings flattened
    findings: list[Finding] = Field(default_factory=list)

    def model_post_init(self, __context: Any) -> None:
        """Aggregate findings."""
        self.findings.extend(self.control_flow_findings)
        self.findings.extend(self.api_usage_findings)