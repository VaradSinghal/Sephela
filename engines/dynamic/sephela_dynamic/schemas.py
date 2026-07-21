"""Pydantic schemas for sandbox artifact formats.

These define the expected JSON structure of each artifact file produced
by the Sandbox Runner (``infra/sandbox/``). Using strict Pydantic models
ensures that malformed or tampered artifacts are rejected early.

Security note (doc 09): All artifacts are treated as **untrusted data** —
they originate from an environment that executed malware. Models validate
structure but content is never eval'd or interpreted as code.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Frida hook trace schema
# ---------------------------------------------------------------------------

class FridaHookType(str, Enum):
    """Categories of Frida API hooks."""

    crypto = "crypto"
    reflection = "reflection"
    dex_loading = "dex_loading"
    network = "network"
    sms = "sms"
    file_io = "file_io"
    process = "process"
    accessibility = "accessibility"
    device_info = "device_info"


class FridaHookEntry(BaseModel):
    """A single intercepted API call from Frida."""

    timestamp_ms: int = Field(..., description="Millis since sandbox boot")
    hook_type: FridaHookType
    class_name: str = Field(..., description="Java class name")
    method_name: str = Field(..., description="Java method name")
    args: list[str] = Field(default_factory=list, description="Stringified arguments")
    return_value: str | None = None
    stack_trace: list[str] = Field(default_factory=list, description="Truncated call stack")
    metadata: dict[str, Any] = Field(default_factory=dict)


class FridaTrace(BaseModel):
    """Complete Frida hook trace from a sandbox run."""

    version: str = "1.0"
    apk_package: str | None = None
    total_hooks: int = 0
    entries: list[FridaHookEntry] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Network trace schema (Suricata EVE / parsed PCAP)
# ---------------------------------------------------------------------------

class NetworkProtocol(str, Enum):
    tcp = "tcp"
    udp = "udp"
    http = "http"
    https = "https"
    dns = "dns"
    tls = "tls"


class NetworkConnection(BaseModel):
    """A single network connection or DNS query."""

    timestamp_ms: int
    protocol: NetworkProtocol
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    dst_hostname: str | None = None  # from DNS or SNI
    bytes_sent: int = 0
    bytes_recv: int = 0
    metadata: dict[str, Any] = Field(default_factory=dict)


class DnsQuery(BaseModel):
    """A DNS lookup performed by the app."""

    timestamp_ms: int
    query: str
    query_type: str = "A"
    response_ips: list[str] = Field(default_factory=list)


class HttpRequest(BaseModel):
    """An HTTP(S) request captured via proxy or Frida."""

    timestamp_ms: int
    method: str
    url: str
    host: str
    user_agent: str | None = None
    content_type: str | None = None
    status_code: int | None = None
    is_cleartext: bool = False  # True if HTTP (not HTTPS)


class TlsInfo(BaseModel):
    """TLS handshake metadata."""

    timestamp_ms: int
    server_name: str  # SNI
    ja3_hash: str | None = None
    certificate_subject: str | None = None
    certificate_issuer: str | None = None
    certificate_serial: str | None = None


class NetworkTrace(BaseModel):
    """Complete network trace from a sandbox run."""

    version: str = "1.0"
    connections: list[NetworkConnection] = Field(default_factory=list)
    dns_queries: list[DnsQuery] = Field(default_factory=list)
    http_requests: list[HttpRequest] = Field(default_factory=list)
    tls_handshakes: list[TlsInfo] = Field(default_factory=list)
    total_bytes_sent: int = 0
    total_bytes_recv: int = 0


# ---------------------------------------------------------------------------
# Logcat schema
# ---------------------------------------------------------------------------

class LogcatLevel(str, Enum):
    verbose = "V"
    debug = "D"
    info = "I"
    warning = "W"
    error = "E"
    fatal = "F"


class LogcatEntry(BaseModel):
    """A single logcat line."""

    timestamp_ms: int
    level: LogcatLevel
    tag: str
    pid: int | None = None
    message: str


class LogcatTrace(BaseModel):
    """Parsed logcat output from a sandbox run."""

    version: str = "1.0"
    entries: list[LogcatEntry] = Field(default_factory=list)
    total_lines: int = 0


# ---------------------------------------------------------------------------
# Sandbox run metadata
# ---------------------------------------------------------------------------

class SandboxMetadata(BaseModel):
    """Metadata about the sandbox execution environment."""

    sandbox_id: str
    emulator_image: str = "android-api-33-x86_64"
    android_api_level: int = 33
    duration_ms: int = 0
    apk_sha256: str | None = None
    apk_package: str | None = None
    frida_version: str | None = None
    network_isolated: bool = True
    exit_reason: str = "completed"  # completed | timeout | crash
