"""Sephela Reporting Engine.

Renders structured analysis results (JSON from the AI/scoring pipeline)
into human-readable and machine-readable formats:

- **JSON** — canonical structured output
- **Markdown** — readable in any Git forge or terminal pager
- **HTML** — styled for browser viewing
- **PDF** — banking-grade executive reports (requires ``weasyprint``)
- **SARIF** — OASIS Static Analysis Results Interchange Format v2.1.0

Public API::

    from sephela_reporting import ReportingEngine

    engine = ReportingEngine()
    artifacts = engine.generate(report_data, formats=["markdown", "sarif"])
"""

from sephela_reporting.engine import ReportingEngine

__all__ = ["ReportingEngine"]
__version__ = "0.1.0"
