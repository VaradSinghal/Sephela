"""Sephela Dynamic Analysis Engine.

Parses runtime artifacts produced by the Android sandbox (Frida hook logs,
network captures, Logcat traces) and synthesizes them into a standardized
Evidence Envelope for the AI reasoning layer.

The engine itself NEVER executes untrusted code. It receives pre-collected
artifacts from the isolated Sandbox Runner (``infra/sandbox/``) and processes
them as structured data.

Public API::

    from sephela_dynamic import analyze

    envelope = analyze(
        artifacts_dir="/tmp/sandbox-output/job-123",
        job_id="job-123",
    )
"""

from sephela_dynamic.pipeline import analyze

__all__ = ["analyze"]
__version__ = "0.1.0"
