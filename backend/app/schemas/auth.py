"""Auth request/response schemas."""

from __future__ import annotations

from pydantic import BaseModel, EmailStr, Field


class Token(BaseModel):
    """An issued token pair.

    ``refresh_token`` is optional so the same model serves the login response and
    any future flow that issues an access token alone.
    """

    access_token: str
    refresh_token: str | None = None
    token_type: str = "bearer"
    expires_in: int | None = Field(default=None, description="Access-token lifetime in seconds.")


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class RefreshRequest(BaseModel):
    refresh_token: str


class UserOut(BaseModel):
    id: str
    email: str
    role: str
    org_id: str | None = None


class AuditEntryOut(BaseModel):
    """One audit-trail row as served to an admin."""

    id: str
    created_at: str
    action: str
    outcome: str
    actor_email: str | None = None
    target_type: str | None = None
    target_id: str | None = None
    ip: str | None = None
    reason: str | None = None


class AuditListOut(BaseModel):
    items: list[AuditEntryOut]
    total: int
