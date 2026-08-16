"""Authentication routes (Phase 14).

Login verifies credentials against the ``users`` table and issues a short access
token plus a refresh token. Two properties are load-bearing and easy to lose in a
later refactor:

- **No user enumeration.** Unknown email, wrong password, and disabled account all
  return the same 401 with the same message, and the unknown-email path still burns
  a password comparison so the timing matches. An endpoint that distinguishes these
  hands an attacker a list of a bank's analyst accounts.
- **Every attempt is audited**, success or failure, and the failure rows are
  committed even though the request errors — an attack leaves a trail precisely
  because it failed.

Enterprise OIDC/SSO does not replace these routes; it registers a resolver behind
``get_current_user`` (see ``app.core.security``). This endpoint remains the local
credential path, which stays useful for break-glass access when the IdP is down.
"""

from __future__ import annotations

import uuid
from typing import TypedDict

from fastapi import APIRouter, Request

from app.api.deps import DbSession
from app.core.config import settings
from app.core.exceptions import UnauthorizedError
from app.core.logging import get_logger
from app.core.security import (
    REFRESH,
    AdminDep,
    CurrentUserDep,
    create_access_token,
    create_refresh_token,
    decode_token,
    dummy_verify,
    verify_password,
)
from app.db.models.audit import AuditAction, AuditOutcome
from app.repositories.audit import AuditRepository
from app.repositories.users import UserRepository
from app.schemas.auth import (
    AuditEntryOut,
    AuditListOut,
    LoginRequest,
    RefreshRequest,
    Token,
    UserOut,
)

logger = get_logger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])

# One message for every credential failure — see the module docstring.
_INVALID = "Invalid email or password."


class _ClientMeta(TypedDict):
    """The request attributes worth recording on an audit row.

    A TypedDict rather than a plain dict so `**meta` at the call sites is checked
    against `AuditRepository.record`'s signature — with a plain dict the unpack is
    opaque and a renamed field would only surface at runtime.
    """

    ip: str | None
    user_agent: str | None
    trace_id: str | None


def _client(request: Request) -> _ClientMeta:
    return _ClientMeta(
        ip=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
        trace_id=getattr(request.state, "trace_id", None),
    )


def _issue(user_id: str, email: str) -> Token:
    return Token(
        access_token=create_access_token(user_id, claims={"email": email}),
        refresh_token=create_refresh_token(user_id, claims={"email": email}),
        expires_in=settings.access_token_expire_minutes * 60,
    )


@router.post("/login", response_model=Token)
async def login(payload: LoginRequest, request: Request, session: DbSession) -> Token:
    """Exchange credentials for an access + refresh token pair."""
    audit = AuditRepository(session)
    meta = _client(request)
    email = payload.email.strip().lower()

    user = await UserRepository(session).get_by_email(email)

    # Equalise the unknown-email path with the known one: same audit write, same
    # hash comparison cost, same response.
    if user is None or not user.hashed_password:
        dummy_verify()
        await audit.record(
            AuditAction.login_failed,
            outcome=AuditOutcome.failure,
            actor_email=email,
            reason="unknown_user",
            **meta,
        )
        await session.commit()  # the attempt is recorded even though we reject
        raise UnauthorizedError(_INVALID)

    if not verify_password(payload.password, user.hashed_password):
        await audit.record(
            AuditAction.login_failed,
            outcome=AuditOutcome.failure,
            actor_id=user.id,
            actor_email=email,
            org_id=user.org_id,
            reason="bad_password",
            **meta,
        )
        await session.commit()
        raise UnauthorizedError(_INVALID)

    if not user.is_active:
        await audit.record(
            AuditAction.login_failed,
            outcome=AuditOutcome.failure,
            actor_id=user.id,
            actor_email=email,
            org_id=user.org_id,
            reason="account_disabled",
            **meta,
        )
        await session.commit()
        raise UnauthorizedError(_INVALID)

    await audit.record(
        AuditAction.login_succeeded,
        actor_id=user.id,
        actor_email=user.email,
        org_id=user.org_id,
        **meta,
    )
    logger.info("login_succeeded", user_id=str(user.id), org_id=str(user.org_id))
    return _issue(str(user.id), user.email)


@router.post("/refresh", response_model=Token)
async def refresh(payload: RefreshRequest, request: Request, session: DbSession) -> Token:
    """Exchange a refresh token for a fresh pair.

    Rotation is unconditional: the caller always receives a new refresh token, so a
    stolen one has a bounded useful life. The user is re-read from the database on
    every refresh, so a deactivated account cannot refresh its way to a new access
    token.
    """
    claims = decode_token(payload.refresh_token, expect=REFRESH)
    try:
        user_id = uuid.UUID(str(claims.get("sub") or ""))
    except ValueError:
        raise UnauthorizedError("Invalid refresh token.") from None

    user = await UserRepository(session).get_by_id(user_id)
    if user is None or not user.is_active:
        raise UnauthorizedError("Invalid refresh token.")

    await AuditRepository(session).record(
        AuditAction.token_refreshed,
        actor_id=user.id,
        actor_email=user.email,
        org_id=user.org_id,
        **_client(request),
    )
    return _issue(str(user.id), user.email)


@router.get("/me", response_model=UserOut)
async def me(current_user: CurrentUserDep) -> UserOut:
    return UserOut(
        id=current_user.id,
        email=current_user.email,
        role=current_user.role,
        org_id=current_user.org_id,
    )


@router.get("/audit", response_model=AuditListOut)
async def read_audit_trail(
    session: DbSession,
    user: AdminDep,
    action: str | None = None,
    limit: int = 100,
) -> AuditListOut:
    """Read this organisation's audit trail. Admin-only.

    Scoped to the caller's own org even for admins — a tenant administrator is not
    a platform operator, and cross-tenant reads belong to a separate operator
    surface, not to this endpoint.
    """
    rows = await AuditRepository(session).list_for_org(
        user.org_uuid, action=action, limit=min(limit, 500)
    )
    items = [
        AuditEntryOut(
            id=str(r.id),
            created_at=r.created_at.isoformat(),
            action=r.action,
            outcome=r.outcome,
            actor_email=r.actor_email,
            target_type=r.target_type,
            target_id=r.target_id,
            ip=r.ip,
            reason=r.reason,
        )
        for r in rows
    ]
    return AuditListOut(items=items, total=len(items))
