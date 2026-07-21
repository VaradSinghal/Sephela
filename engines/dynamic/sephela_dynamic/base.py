"""Extractor framework — the contract every dynamic extractor implements.

Mirrors the static engine's extractor contract (``engines/static/base.py``).
Each extractor parses one class of sandbox artifact (Frida hooks, network
captures, Logcat) and returns structured evidence + findings.

The pipeline catches any exception so one extractor's failure degrades to
``partial`` rather than crashing (isolation guarantee).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path

from sephela_dynamic.envelope import Finding


@dataclass
class ArtifactsContext:
    """Context for dynamic extractors.

    The ``artifacts_dir`` contains the raw output from the sandbox runner:
    - ``frida_trace.json`` — Frida API hook log
    - ``network.json`` — Suricata EVE / parsed PCAP alerts
    - ``logcat.txt`` — Android system log
    - ``metadata.json`` — Sandbox run metadata (duration, emulator info)

    Attributes:
        artifacts_dir: Path to the sandbox output directory.
        shared: Evidence from already-run extractors, keyed by name.
    """

    artifacts_dir: Path
    shared: dict[str, dict[str, object]] = field(default_factory=dict)

    def artifact_path(self, filename: str) -> Path:
        """Return the full path to a sandbox artifact file."""
        return self.artifacts_dir / filename

    def read_artifact(self, filename: str) -> str | None:
        """Read a text artifact, returning None if missing."""
        path = self.artifact_path(filename)
        if path.is_file():
            return path.read_text(encoding="utf-8")
        return None


@dataclass
class ExtractorResult:
    """What an extractor returns: evidence blob + normalized findings."""

    evidence: dict[str, object] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)


class DynamicExtractor(ABC):
    """Base class for all dynamic analysis extractors."""

    #: stable identifier used as the evidence key + provenance name
    name: str = "extractor"
    #: file(s) this extractor expects in the artifacts directory
    required_artifacts: list[str] = []

    def can_run(self, ctx: ArtifactsContext) -> bool:
        """Check if required artifacts are present."""
        return all(ctx.artifact_path(f).is_file() for f in self.required_artifacts)

    @abstractmethod
    def extract(self, ctx: ArtifactsContext) -> ExtractorResult:
        """Run the extraction. May raise — the pipeline isolates failures."""
