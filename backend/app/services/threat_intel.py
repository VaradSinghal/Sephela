"""Threat-intel stage support — config → providers, and DB → indicators.

The engine is a pure function (indicators in, envelope out), so everything
environment-shaped lives here: which providers the deployment has keys for, and
which indicators this job's upstream stages actually produced.

Indicators come from the normalized ``findings`` table rather than from each
engine's ``evidence`` JSONB. That table is the one cross-engine contract with a
fixed schema (docs/architecture/04-data-model.md), so a new engine becomes a
source of indicators simply by emitting url/ip/cert/network findings — no change
here.

Ordering matters and is deliberate: dynamic-analysis findings are gathered first,
because they were *observed at runtime* while static findings were scraped out of
a binary's strings. When the per-class caps bite, the observed indicators are the
ones worth spending quota on.
"""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING, Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, settings
from app.core.logging import get_logger
from app.db.models.analysis import Finding, Sample

if TYPE_CHECKING:  # pragma: no cover — engine is an optional worker dependency
    from sephela_threat_intel.base import Provider
    from sephela_threat_intel.iocs import Ioc

logger = get_logger(__name__)


class ThreatIntelUnavailableError(RuntimeError):
    """The engine package is not installed in this worker."""


def engine_module() -> tuple[Any, str]:
    """Import the threat-intel engine lazily.

    Mirrors ``app.tasks.dynamic._engine``: engines are separate distributions, so
    a backend that doesn't run this stage needn't install it, and a missing
    install surfaces as a failed *stage* with a clear message rather than a worker
    that won't boot.
    """
    try:
        import sephela_threat_intel
        from sephela_threat_intel.pipeline import ENGINE_VERSION
    except ImportError as exc:  # pragma: no cover — environment-dependent
        raise ThreatIntelUnavailableError(
            "sephela-threat-intel-engine is not installed in the worker environment "
            "(pip install -e engines/threat_intel)."
        ) from exc
    return sephela_threat_intel, ENGINE_VERSION


def api_keys(config: Settings | None = None) -> dict[str, str | None]:
    """Map provider names onto configured API keys.

    Keys are named per provider rather than as one blob so a deployment can hold
    only the feeds it has paid for, and so a missing key is visibly a *config*
    gap rather than a code path.
    """
    cfg = config or settings
    return {
        "virustotal": cfg.virustotal_api_key,
        "otx": cfg.otx_api_key,
        "abuseipdb": cfg.abuseipdb_api_key,
        "urlhaus": cfg.urlhaus_api_key,
        "bazaar": cfg.bazaar_api_key,
    }


def build_providers(config: Settings | None = None) -> list[Provider]:
    """Instantiate the providers this deployment can actually call."""
    from sephela_threat_intel.providers import build_providers as _build

    providers = _build(api_keys(config))
    logger.info("threat_intel_providers", providers=[p.name for p in providers])
    return providers


#: Engines whose findings are gathered first, in this order. Runtime-observed
#: indicators outrank statically-scraped ones when the caps apply.
ENGINE_PRIORITY = ("dynamic", "static", "code_intel")

#: Finding types worth harvesting. Anything else (permissions, obfuscation) has
#: no indicator in it, so querying for it would only add rows to scan.
HARVEST_TYPES = ("url", "ip", "domain", "cert", "network", "behavior", "runtime_api")

#: Upper bound on finding rows scanned per job. A packed APK can produce
#: thousands of url-shaped strings; the engine's per-class caps then reduce these
#: to the enrichable set.
MAX_FINDING_ROWS = 2000


async def gather_iocs(
    session: AsyncSession, job_id: uuid.UUID, sample: Sample
) -> list[Ioc]:
    """Collect this job's indicators: the sample's digests plus upstream findings.

    Returns them in priority order — sample hashes first (the single most
    valuable lookup: "is this exact APK known malware?"), then dynamic, then
    static findings.
    """
    from sephela_threat_intel.sources import iocs_from_findings, sample_iocs

    iocs = sample_iocs(sha256=sample.sha256, sha1=sample.sha1, md5=sample.md5)

    rows = await _finding_rows(session, job_id)
    iocs.extend(iocs_from_findings(rows))

    logger.info(
        "threat_intel_iocs_gathered",
        job_id=str(job_id),
        finding_rows=len(rows),
        iocs=len(iocs),
    )
    return iocs


async def _finding_rows(session: AsyncSession, job_id: uuid.UUID) -> list[dict[str, Any]]:
    """Fetch harvestable findings, ordered by engine priority.

    Sorting happens in Python rather than SQL because the priority is a short
    fixed list, not a column — encoding it as a CASE expression would be more
    SQL for no gain.
    """
    stmt = (
        select(Finding.source_engine, Finding.type, Finding.detail)
        .where(Finding.job_id == job_id, Finding.type.in_(HARVEST_TYPES))
        .limit(MAX_FINDING_ROWS)
    )
    result = await session.execute(stmt)

    rows = [
        {"source_engine": engine, "type": type_, "detail": detail}
        for engine, type_, detail in result.all()
    ]

    def rank(row: dict[str, Any]) -> int:
        engine = str(row.get("source_engine") or "")
        return ENGINE_PRIORITY.index(engine) if engine in ENGINE_PRIORITY else len(
            ENGINE_PRIORITY
        )

    rows.sort(key=rank)
    return rows
