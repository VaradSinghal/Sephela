"""Shared FastAPI dependencies for the API layer."""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.storage import get_storage
from app.storage.base import StorageBackend

DbSession = Annotated[AsyncSession, Depends(get_db)]
# app.core.security declares the same annotation privately (core must not import
# the API layer). Both resolve to the one get_db dependency, so overriding get_db in
# a test replaces the session everywhere.


def storage_dep() -> StorageBackend:
    return get_storage()


Storage = Annotated[StorageBackend, Depends(storage_dep)]
