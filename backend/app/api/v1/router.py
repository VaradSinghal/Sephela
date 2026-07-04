"""Aggregates all v1 routers under the versioned prefix."""

from __future__ import annotations

from fastapi import APIRouter

from app.api.v1.routers import auth, health

api_router = APIRouter()
api_router.include_router(health.router)
api_router.include_router(auth.router)
