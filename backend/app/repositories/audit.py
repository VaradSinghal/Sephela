"""Audit-trail writes and queries.

Deliberately offers no update or delete: the append-only guarantee is worth more
than the convenience of fixing a bad row, and a repository with an ``update`` method
is an invitation to launder the trail.

Auditing must not be able to break the action it records. ``record`` therefore
swallows its own failures and logs them loudly rather than raising — an audit-table
outage should degrade observability, not reject a bank's upload. The inverse
(silently losing the trail) is handled by alerting on the emitted error, which
belongs in the same monitoring as any other write failure.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import get_logger
from app.db.models.audit import AuditAction, AuditLog, AuditOutcome

logger = get_logger(__name__)

# Keys whose values must never reach the trail even if a caller passes them.
# The audit log is widely readable by design (compliance, investigations), so it is
# the last place a credential should come to rest.
_REDACTED_KEYS = {"password", "token", "access_token", "refresh_token", "secret", "api_key"}


def _scrub(detail: dict[str, Any] | None) -> dict[str, Any] | None:
    if not detail:
        return None
    return {
        key: ("[redacted]" if key.lower() in _REDACTED_KEYS else value)
        for key, value in detail.items()
    }


class AuditRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def record(
        self,
        action: AuditAction | str,
        *,
        outcome: AuditOutcome | str = AuditOutcome.success,
        actor_id: uuid.UUID | None = None,
        actor_email: str | None = None,
        org_id: uuid.UUID | None = None,
        target_type: str | None = None,
        target_id: str | None = None,
        ip: str | None = None,
        user_agent: str | None = None,
        trace_id: str | None = None,
        reason: str | None = None,
        detail: dict[str, Any] | None = None,
    ) -> AuditLog | None:
        """Append one row. Returns None if the write failed (never raises).

        The row is flushed but not committed: it joins the caller's transaction so a
        rolled-back action does not leave a trail claiming it happened. Actions that
        must be recorded even on failure (a rejected login) are committed by their
        caller explicitly.
        """
        entry = AuditLog(
            action=action.value if isinstance(action, AuditAction) else str(action),
            outcome=outcome.value if isinstance(outcome, AuditOutcome) else str(outcome),
            actor_id=actor_id,
            actor_email=actor_email,
            org_id=org_id,
            target_type=target_type,
            target_id=target_id,
            ip=ip,
            user_agent=user_agent and user_agent[:512],
            trace_id=trace_id,
            reason=reason,
            detail=_scrub(detail),
        )
        try:
            self.session.add(entry)
            await self.session.flush()
            return entry
        except Exception:  # noqa: BLE001
            logger.exception(
                "audit_write_failed",
                action=entry.action,
                target_type=target_type,
                target_id=target_id,
            )
            return None

    async def list_for_org(
        self,
        org_id: uuid.UUID | None,
        *,
        action: str | None = None,
        limit: int = 100,
    ) -> list[AuditLog]:
        """Read an org's trail, newest first.

        ``org_id=None`` reads across every tenant and is only reachable from
        admin-gated routes — see the audit router.
        """
        stmt = select(AuditLog).order_by(desc(AuditLog.created_at)).limit(limit)
        if org_id is not None:
            stmt = stmt.where(AuditLog.org_id == org_id)
        if action is not None:
            stmt = stmt.where(AuditLog.action == action)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())
