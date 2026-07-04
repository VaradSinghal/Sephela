"""Authentication routes (PLACEHOLDER — Phase 2).

These routes establish the API surface (docs/architecture/06-api-spec.md) so the
frontend and integrations can build against a stable contract. Real credential
verification, refresh rotation, and OIDC/SSO exchange arrive in a later phase.
The route signatures will not change when that happens.
"""

from __future__ import annotations

from fastapi import APIRouter

from app.core.security import CurrentUserDep, create_access_token
from app.schemas.auth import LoginRequest, Token, UserOut

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login", response_model=Token)
async def login(payload: LoginRequest) -> Token:
    """Issue an access token.

    PLACEHOLDER: does not verify credentials against the DB yet. It mints a
    signed token so downstream auth wiring can be exercised end-to-end.
    """
    token = create_access_token(
        subject=payload.email,
        claims={"email": payload.email, "role": "analyst"},
    )
    return Token(access_token=token)


@router.get("/me", response_model=UserOut)
async def me(current_user: CurrentUserDep) -> UserOut:
    return UserOut(
        id=current_user.id,
        email=current_user.email,
        role=current_user.role,
        org_id=current_user.org_id,
    )
