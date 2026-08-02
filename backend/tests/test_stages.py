"""Tests for the envelope → database mapping in app.services.stages.

These cover the pure functions, which is where the contract interpretation lives:
a malformed or hostile envelope must degrade gracefully, never raise, and never
be silently read as a clean success.
"""

from __future__ import annotations

import uuid

from app.db.models.analysis import StageStatus
from app.services.stages import (
    envelope_error_summary,
    envelope_status,
    normalize_findings,
)

JOB_ID = uuid.uuid4()


def _envelope(**overrides: object) -> dict:
    base = {
        "envelope_version": "1.0",
        "engine": {"name": "dynamic", "version": "1.0.0"},
        "status": "ok",
        "evidence": {},
        "findings": [],
        "errors": [],
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# envelope_status
# ---------------------------------------------------------------------------


def test_envelope_status_maps_known_values() -> None:
    assert envelope_status(_envelope(status="ok")) is StageStatus.ok
    assert envelope_status(_envelope(status="partial")) is StageStatus.partial
    assert envelope_status(_envelope(status="failed")) is StageStatus.failed


def test_unknown_status_degrades_to_partial_not_ok() -> None:
    """An unrecognized status must never read as a clean success."""
    assert envelope_status(_envelope(status="bogus")) is StageStatus.partial
    assert envelope_status(_envelope(status=None)) is StageStatus.partial
    assert envelope_status({}) is StageStatus.partial


# ---------------------------------------------------------------------------
# envelope_error_summary
# ---------------------------------------------------------------------------


def test_error_summary_joins_extractor_failures() -> None:
    payload = _envelope(
        status="partial",
        errors=[
            {"extractor": "frida", "message": "trace unreadable"},
            {"extractor": "network", "message": "no pcap"},
        ],
    )
    assert envelope_error_summary(payload) == "frida: trace unreadable; network: no pcap"


def test_error_summary_is_none_when_clean() -> None:
    assert envelope_error_summary(_envelope()) is None
    assert envelope_error_summary({}) is None


def test_error_summary_survives_malformed_entries() -> None:
    payload = _envelope(errors=["not-a-dict", {"extractor": "logcat"}])
    assert envelope_error_summary(payload) == "logcat: "


def test_error_summary_is_truncated() -> None:
    payload = _envelope(errors=[{"extractor": "x", "message": "y" * 9000}])
    summary = envelope_error_summary(payload)
    assert summary is not None
    assert len(summary) <= 4000


# ---------------------------------------------------------------------------
# normalize_findings
# ---------------------------------------------------------------------------


def _normalize(payload: dict) -> list:
    return normalize_findings(payload, job_id=JOB_ID, engine_name="dynamic")


def test_normalize_maps_all_fields() -> None:
    payload = _envelope(
        findings=[
            {
                "id": "dyn-sms-001",
                "type": "sms",
                "severity": "critical",
                "confidence": 0.9,
                "detail": "Intercepted incoming SMS",
                "provenance": {"extractor": "frida", "locator": "frida_trace:line:42"},
                "mappings": {"mitre": ["T1417"], "owasp_mobile": ["M2"]},
            }
        ]
    )
    (row,) = _normalize(payload)

    assert row.job_id == JOB_ID
    assert row.source_engine == "dynamic"
    assert row.finding_id == "dyn-sms-001"
    assert row.type == "sms"
    assert row.severity == "critical"
    assert row.confidence == 0.9
    assert row.detail == "Intercepted incoming SMS"
    assert row.provenance == {"extractor": "frida", "locator": "frida_trace:line:42"}
    assert row.mitre == ["T1417"]
    assert row.owasp_mobile == ["M2"]


def test_findings_without_id_get_positional_fallback() -> None:
    payload = _envelope(findings=[{"type": "network", "detail": "beacon"}])
    (row,) = _normalize(payload)
    assert row.finding_id == "dynamic-0"
    assert row.severity == "info"  # documented default
    assert row.confidence is None


def test_duplicate_ids_are_collapsed() -> None:
    """The unique constraint must not be reachable from one envelope."""
    payload = _envelope(
        findings=[
            {"id": "same", "type": "network", "detail": "a"},
            {"id": "same", "type": "crypto", "detail": "b"},
        ]
    )
    rows = _normalize(payload)
    assert len(rows) == 1
    assert rows[0].detail == "a"  # first wins


def test_findings_missing_a_type_are_dropped() -> None:
    payload = _envelope(
        findings=[
            {"id": "a", "detail": "no type"},
            {"id": "b", "type": "", "detail": "empty type"},
            {"id": "c", "type": "network", "detail": "keeper"},
        ]
    )
    rows = _normalize(payload)
    assert [r.finding_id for r in rows] == ["c"]


def test_malformed_findings_never_raise() -> None:
    """Artifacts come from a machine that ran malware — treat them as hostile."""
    payload = _envelope(
        findings=[
            "a string",
            None,
            42,
            {"type": "network", "mappings": "not-a-dict", "provenance": "nope"},
        ]
    )
    rows = _normalize(payload)
    assert len(rows) == 1
    assert rows[0].provenance is None
    assert rows[0].mitre == []
    assert rows[0].owasp_mobile == []


def test_non_list_findings_yield_nothing() -> None:
    assert _normalize(_envelope(findings="nope")) == []
    assert _normalize({}) == []


def test_oversized_strings_are_truncated_to_column_widths() -> None:
    payload = _envelope(
        findings=[{"id": "x" * 500, "type": "y" * 500, "severity": "z" * 500}]
    )
    (row,) = _normalize(payload)
    assert len(row.finding_id) == 128
    assert len(row.type) == 64
    assert len(row.severity) == 16


def test_evidence_id_is_threaded_through() -> None:
    evidence_id = uuid.uuid4()
    payload = _envelope(findings=[{"id": "a", "type": "network"}])
    (row,) = normalize_findings(
        payload, job_id=JOB_ID, engine_name="dynamic", evidence_id=evidence_id
    )
    assert row.evidence_id == evidence_id
