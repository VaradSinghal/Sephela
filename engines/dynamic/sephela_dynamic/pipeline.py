"""Dynamic Analysis pipeline — runs extractors, isolates failures, emits envelope.

This is the engine's public entrypoint. It mirrors the static engine's pipeline
pattern (``engines/static/sephela_static/pipeline.py``):
- success  → evidence merged under the extractor's name, findings appended
- failure  → recorded in ``errors``; the run continues (status becomes ``partial``)

The orchestration worker calls ``analyze()`` and persists the returned
Evidence Envelope.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from sephela_dynamic.base import ArtifactsContext, DynamicExtractor
from sephela_dynamic.envelope import (
    ENVELOPE_VERSION,
    EngineInfo,
    EvidenceEnvelope,
    ExtractorError,
    Status,
)
from sephela_dynamic.extractors import default_extractors
from sephela_dynamic.schemas import SandboxMetadata

ENGINE_NAME = "dynamic"
ENGINE_VERSION = "1.0.0"


def analyze(
    artifacts_dir: str | Path,
    *,
    job_id: str | None = None,
    extractors: list[DynamicExtractor] | None = None,
) -> EvidenceEnvelope:
    """Run the dynamic-analysis extractor chain over sandbox artifacts.

    Never raises for extractor-level problems — those are captured as partial
    failures. Only a completely unreadable artifacts directory will propagate.

    Args:
        artifacts_dir: Path to the sandbox output directory containing
            frida_trace.json, network.json, logcat.json, and metadata.json.
        job_id: Optional job identifier for tracing.
        extractors: Override the default extractor chain (for testing).

    Returns:
        A complete Evidence Envelope with dynamic analysis findings.
    """
    path = Path(artifacts_dir)
    if not path.is_dir():
        raise FileNotFoundError(f"Artifacts directory does not exist: {path}")

    ctx = ArtifactsContext(artifacts_dir=path)
    chain = extractors if extractors is not None else default_extractors()

    envelope = EvidenceEnvelope(
        envelope_version=ENVELOPE_VERSION,
        job_id=job_id,
        engine=EngineInfo(name=ENGINE_NAME, version=ENGINE_VERSION),
        produced_at=datetime.now(timezone.utc).isoformat(),
        status=Status.ok,
    )

    # Load sandbox metadata if available
    metadata_raw = ctx.read_artifact("metadata.json")
    if metadata_raw is not None:
        try:
            meta = SandboxMetadata.model_validate(json.loads(metadata_raw))
            envelope.apk_sha256 = meta.apk_sha256
            envelope.sandbox_duration_ms = meta.duration_ms
            envelope.evidence["sandbox_metadata"] = {
                "sandbox_id": meta.sandbox_id,
                "emulator_image": meta.emulator_image,
                "android_api_level": meta.android_api_level,
                "duration_ms": meta.duration_ms,
                "network_isolated": meta.network_isolated,
                "exit_reason": meta.exit_reason,
                "frida_version": meta.frida_version,
            }
        except Exception as exc:
            envelope.errors.append(
                ExtractorError(
                    extractor="sandbox_metadata",
                    message=f"Failed to parse metadata.json: {exc}",
                )
            )

    ran = 0
    skipped = 0
    for extractor in chain:
        # Skip extractors whose required artifacts are missing
        if not extractor.can_run(ctx):
            skipped += 1
            continue

        try:
            result = extractor.extract(ctx)
        except Exception as exc:  # noqa: BLE001 — isolation is the whole point
            envelope.errors.append(
                ExtractorError(
                    extractor=extractor.name,
                    message=f"{type(exc).__name__}: {exc}",
                )
            )
            continue

        ran += 1
        envelope.evidence[extractor.name] = result.evidence
        ctx.shared[extractor.name] = result.evidence
        envelope.findings.extend(result.findings)

    if envelope.errors:
        envelope.status = Status.failed if ran == 0 else Status.partial
    elif ran == 0 and skipped > 0:
        envelope.status = Status.partial
        envelope.errors.append(
            ExtractorError(
                extractor="pipeline",
                message=f"No extractors could run — {skipped} skipped due to missing artifacts.",
            )
        )

    return envelope
