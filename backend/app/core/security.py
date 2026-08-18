"""Authentication and authorization (Phase 14).

Two rules shape this module, both of which the Phase-2 placeholder broke:

**The token is an identifier, not a source of truth.** A bearer token says *who is
asking*; it does not say what their role is or which org they belong to. Those are
read from the ``users`` row on every request. Trusting `role`/`org_id` claims from
the token means anyone who ever holds a signed token can mint themselves admin on
another tenant, and a deactivated user keeps access until their token expires.

**One seam for every identity provider.** ``get_current_user`` resolves a principal
through a :class:`PrincipalResolver`; local JWTs are one implementation. Enterprise
OIDC/SSO plugs in by registering a resolver that validates the provider's token and
maps its claims onto a local user — no route signature changes. See
``resolve_principal`` for the contract an OIDC resolver must satisfy.
"""

from __future__ import annotations

import base64
import functools
import hashlib
import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, Protocol

import bcrypt
import jwt
from fastapi import Depends
from fastapi.security import OAuth2PasswordBearer
from jwt import PyJWTError
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.exceptions import ForbiddenError, UnauthorizedError
from app.db.models.identity import Role, User
from app.db.session import get_db
from app.repositories.users import UserRepository

# Declared here rather than imported from app.api.deps: core must not depend on
# the API layer. app.api.deps re-exports the same annotation for route use.
_SessionDep = Annotated[AsyncSession, Depends(get_db)]

oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl=f"{settings.api_v1_prefix}/auth/login", auto_error=False
)

# Token kinds. An access token must never be accepted where a refresh token is
# required, or vice versa — otherwise a long-lived refresh token doubles as an
# access token and defeats the short access TTL entirely.
ACCESS = "access"
REFRESH = "refresh"

# Privilege ordering. Roles are a ladder, not a set: an admin can do anything an
# analyst can. Comparing positions here keeps every endpoint's requirement to a
# single minimum role rather than an enumeration that goes stale when roles change.
_ROLE_ORDER: dict[str, int] = {
    Role.viewer.value: 0,
    Role.analyst.value: 1,
    Role.admin.value: 2,
}


class CurrentUser(BaseModel):
    """An authenticated principal, hydrated from the database."""

    id: str
    email: str
    role: str  # admin|analyst|viewer — from the users row, never from a claim
    org_id: str | None = None

    @property
    def org_uuid(self) -> uuid.UUID | None:
        return uuid.UUID(self.org_id) if self.org_id else None

    def has_role(self, minimum: Role | str) -> bool:
        """True if this principal's role is at least *minimum* on the ladder."""
        wanted = minimum.value if isinstance(minimum, Role) else str(minimum)
        return _ROLE_ORDER.get(self.role, -1) >= _ROLE_ORDER.get(wanted, 99)

    @classmethod
    def from_row(cls, user: User) -> CurrentUser:
        return cls(
            id=str(user.id),
            email=user.email,
            role=user.role.value if isinstance(user.role, Role) else str(user.role),
            org_id=str(user.org_id) if user.org_id else None,
        )


# ---------------------------------------------------------------------------
# Passwords
# ---------------------------------------------------------------------------


# Cost factor. Each increment doubles the work; 12 is the current common floor for
# interactive logins and costs roughly a quarter-second here.
_BCRYPT_ROUNDS = 12


def _prehash(password: str) -> bytes:
    """Condense a password to a fixed 44 bytes for bcrypt.

    bcrypt ignores everything past 72 bytes and stops at the first NUL, so long
    passphrases would be silently truncated to their first 72 bytes — two different
    passwords sharing a prefix would validate against each other's hash. Hashing to
    SHA-256 first and base64-encoding the digest keeps the input well inside the
    limit and free of NULs, so the entire password contributes. This is the standard
    ``bcrypt_sha256`` construction.
    """
    digest = hashlib.sha256(password.encode("utf-8")).digest()
    return base64.b64encode(digest)


def hash_password(password: str) -> str:
    """Hash a password for storage. Salt is generated per call."""
    return bcrypt.hashpw(_prehash(password), bcrypt.gensalt(_BCRYPT_ROUNDS)).decode()


def verify_password(plain: str, hashed: str) -> bool:
    """Constant-time check of *plain* against a stored hash.

    A malformed or empty stored hash returns False rather than raising: a corrupt
    row must fail the login, not 500 the endpoint (and not, by erroring differently,
    reveal that the row exists).
    """
    if not hashed:
        return False
    try:
        return bcrypt.checkpw(_prehash(plain), hashed.encode())
    except (ValueError, TypeError):
        return False


@functools.lru_cache(maxsize=1)
def _dummy_hash() -> str:
    """A real hash to compare against when no user was found.

    Computed on first use rather than at import: hashing is deliberately slow, and
    an import-time cost that can also raise turns a password-hashing problem into
    an app that will not boot.
    """
    return hash_password("sephela-timing-equalizer")


def dummy_verify() -> None:
    """Burn a hash comparison against a throwaway value.

    Called when login is given an unknown email so the response takes about as long
    as it does for a known one. Without it, response latency distinguishes real
    accounts from fake ones and the endpoint becomes a user-enumeration oracle
    regardless of how carefully the error message is worded.
    """
    verify_password("not-the-password", _dummy_hash())


# ---------------------------------------------------------------------------
# Tokens
# ---------------------------------------------------------------------------


def _encode(subject: str, token_type: str, ttl: timedelta, claims: dict[str, Any] | None) -> str:
    now = datetime.now(UTC)
    payload: dict[str, Any] = {
        "sub": subject,
        "iat": now,
        "exp": now + ttl,
        "typ": token_type,
        # A unique id per token, so a future revocation list has something to
        # key on without invalidating every token the user holds.
        "jti": uuid.uuid4().hex,
        **(claims or {}),
    }
    return jwt.encode(payload, settings.secret_key, algorithm=settings.algorithm)


def create_access_token(subject: str, claims: dict[str, Any] | None = None) -> str:
    """Mint a short-lived access token.

    ``claims`` is for diagnostics only (e.g. email for log correlation) — nothing
    in it is used for authorization decisions; see the module docstring.
    """
    return _encode(subject, ACCESS, timedelta(minutes=settings.access_token_expire_minutes), claims)


def create_refresh_token(subject: str, claims: dict[str, Any] | None = None) -> str:
    """Mint a long-lived refresh token, exchangeable for a new access token."""
    return _encode(subject, REFRESH, timedelta(days=settings.refresh_token_expire_days), claims)


def decode_token(token: str, *, expect: str | None = None) -> dict[str, Any]:
    """Verify a token's signature and expiry, and optionally its kind.

    Args:
        token:  The encoded JWT.
        expect: ``ACCESS`` or ``REFRESH``. When given, a token of the other kind
                is rejected even though its signature is valid.
    """
    try:
        payload: dict[str, Any] = jwt.decode(
            token, settings.secret_key, algorithms=[settings.algorithm]
        )
    except PyJWTError as exc:
        raise UnauthorizedError("Invalid or expired token.") from exc

    if expect is not None and payload.get("typ") != expect:
        raise UnauthorizedError(f"Expected a {expect} token.")
    return payload


# ---------------------------------------------------------------------------
# Principal resolution — the provider seam
# ---------------------------------------------------------------------------


class PrincipalResolver(Protocol):
    """Turns a bearer token into a local user row, or returns None to abstain.

    An enterprise OIDC/SSO resolver implements exactly this: validate the
    provider's token (JWKS signature, issuer, audience, expiry), read the subject
    or email claim, look the user up locally, and return the row. Returning None
    lets the next resolver try, so several providers can coexist.

    Whatever the provider says about groups or roles, the returned row's ``role``
    and ``org_id`` are what the platform authorizes against — provisioning a user
    is a separate, deliberate act from authenticating one.
    """

    async def __call__(self, token: str, users: UserRepository) -> User | None: ...


async def resolve_local_jwt(token: str, users: UserRepository) -> User | None:
    """Resolve a principal from a token this platform issued itself."""
    payload = decode_token(token, expect=ACCESS)
    subject = str(payload.get("sub") or "")
    try:
        user_id = uuid.UUID(subject)
    except ValueError:
        # Tokens minted by the Phase-2 placeholder carried an email in `sub`.
        # They are not valid principals any more; say so rather than guessing.
        raise UnauthorizedError("Token subject is not a user id.") from None
    return await users.get_by_id(user_id)


# Ordered chain. Append an OIDC resolver here (or in an app-factory hook) to
# accept provider tokens alongside locally issued ones.
_RESOLVERS: list[PrincipalResolver] = [resolve_local_jwt]


def register_resolver(resolver: PrincipalResolver) -> None:
    """Add an identity provider to the resolution chain."""
    _RESOLVERS.append(resolver)


async def resolve_principal(token: str, users: UserRepository) -> CurrentUser:
    """Resolve a bearer token to a principal via the resolver chain."""
    for resolver in _RESOLVERS:
        user = await resolver(token, users)
        if user is None:
            continue
        if not user.is_active:
            # Checked here rather than at login so deactivating a user takes
            # effect on their next request, not when their token expires.
            raise UnauthorizedError("Account is disabled.")
        return CurrentUser.from_row(user)
    raise UnauthorizedError("Token does not identify a known user.")


async def get_current_user(
    session: _SessionDep,
    token: Annotated[str | None, Depends(oauth2_scheme)],
) -> CurrentUser:
    """FastAPI dependency: the authenticated principal for this request."""
    if not token:
        raise UnauthorizedError("Authentication required.")
    return await resolve_principal(token, UserRepository(session))


CurrentUserDep = Annotated[CurrentUser, Depends(get_current_user)]


# ---------------------------------------------------------------------------
# RBAC
# ---------------------------------------------------------------------------


def require_role(minimum: Role) -> Any:
    """Build a dependency that admits only principals at or above *minimum*.

    Used as ``user: Annotated[CurrentUser, Depends(require_role(Role.analyst))]``
    so the endpoint still receives the principal it needs for tenancy scoping —
    a guard that returns nothing invites a second, unguarded lookup.
    """

    async def _guard(user: CurrentUserDep) -> CurrentUser:
        if not user.has_role(minimum):
            raise ForbiddenError(f"This action requires the '{minimum.value}' role or higher.")
        return user

    return _guard


ViewerDep = Annotated[CurrentUser, Depends(require_role(Role.viewer))]
AnalystDep = Annotated[CurrentUser, Depends(require_role(Role.analyst))]
AdminDep = Annotated[CurrentUser, Depends(require_role(Role.admin))]
