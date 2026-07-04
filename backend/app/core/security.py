"""Authentication placeholder (Phase 2).

Provides password hashing + JWT issue/verify and a ``get_current_user``
dependency stub. This is intentionally minimal — enterprise OIDC/SSO slots in
behind the same ``get_current_user`` dependency later (Phase 14) without
changing route signatures. RBAC roles are modeled but not yet enforced.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Annotated, Any

from fastapi import Depends
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel

from app.core.config import settings
from app.core.exceptions import UnauthorizedError

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# tokenUrl is documentation-only for now; the login route lands in a later phase.
oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl=f"{settings.api_v1_prefix}/auth/login", auto_error=False
)


class CurrentUser(BaseModel):
    """Minimal authenticated principal (placeholder)."""

    id: str
    email: str
    role: str = "analyst"  # admin|analyst|viewer
    org_id: str | None = None


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def create_access_token(subject: str, claims: dict[str, Any] | None = None) -> str:
    expire = datetime.now(timezone.utc) + timedelta(
        minutes=settings.access_token_expire_minutes
    )
    to_encode: dict[str, Any] = {"sub": subject, "exp": expire, **(claims or {})}
    return jwt.encode(to_encode, settings.secret_key, algorithm=settings.algorithm)


def decode_token(token: str) -> dict[str, Any]:
    try:
        return jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
    except JWTError as exc:  # noqa: TRY003
        raise UnauthorizedError("Invalid or expired token.") from exc


async def get_current_user(
    token: Annotated[str | None, Depends(oauth2_scheme)],
) -> CurrentUser:
    """Resolve the current principal from a bearer token.

    PLACEHOLDER: decodes a JWT and trusts its claims. Real user lookup,
    revocation, and OIDC exchange arrive in a later phase.
    """
    if not token:
        raise UnauthorizedError("Authentication required.")
    payload = decode_token(token)
    return CurrentUser(
        id=str(payload.get("sub", "")),
        email=str(payload.get("email", "")),
        role=str(payload.get("role", "analyst")),
        org_id=payload.get("org_id"),
    )


CurrentUserDep = Annotated[CurrentUser, Depends(get_current_user)]
