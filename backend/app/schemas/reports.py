"""Report response schemas (docs/architecture/06-api-spec.md).

The report is served in two pieces on purpose. ``ReportOut`` is the structured
report — the score, its per-domain decomposition, and the findings — which is what
the dashboard renders and what an integration consumes. The rendered files
(PDF/HTML/Markdown/SARIF) are streamed separately by format, because a client
displaying a report should not have to download a megabyte of PDF to show a
number.
"""

from __future__ import annotations

import uuid
from typing import Any

from pydantic import BaseModel


class DomainScoreOut(BaseModel):
    """One scoring domain's contribution to the final score."""

    domain: str
    weight: float
    raw_score: float
    weighted_score: float
    finding_count: int = 0
    description: str = ""


class SynergyBonusOut(BaseModel):
    """A synergy rule that fired.

    Surfaced because it is the least obvious part of the score: permissions and
    behaviours that are unremarkable alone can be damning together, and an
    analyst defending the score needs to see which combination triggered.
    """

    rule_id: str
    name: str
    description: str
    bonus: float
    matched_domains: list[str] = []
    matched_techniques: list[str] = []
    confidence: float = 0.0


class ScoreBreakdownOut(BaseModel):
    """The full deterministic scoring result behind the headline number."""

    final_score: float
    base_score: float
    synergy_bonus: float
    tier: str
    confidence: float
    primary_category: str | None = None
    secondary_categories: list[str] = []
    domain_scores: list[DomainScoreOut] = []
    synergy_bonuses: list[SynergyBonusOut] = []
    key_findings: list[str] = []
    scoring_version: str | None = None


class ReportOut(BaseModel):
    """A job's structured report plus the formats available for download."""

    job_id: uuid.UUID
    report_id: str
    generated_at: str | None = None
    # Present whenever the scoring stage ran; absent for a job that produced no
    # findings to score.
    score: ScoreBreakdownOut | None = None
    report: dict[str, Any] = {}
    # format name → download path, e.g. {"pdf": "/api/v1/jobs/<id>/report/pdf"}
    formats: dict[str, str] = {}
    # Why the report is incomplete, when it is (e.g. an unavailable renderer).
    warnings: list[str] = []
