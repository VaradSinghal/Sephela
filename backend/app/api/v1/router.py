"""Aggregates all v1 routers under the versioned prefix."""

from __future__ import annotations

from fastapi import APIRouter

from app.api.v1.routers import auth, health, jobs, reports, uploads

api_router = APIRouter()
api_router.include_router(health.router)
api_router.include_router(auth.router)
api_router.include_router(uploads.router)
api_router.include_router(jobs.router)
# Shares the /jobs prefix: a report is a projection of a job, not its own
# resource. Registered after jobs so the more specific /report paths are declared
# alongside, never shadowing /jobs/{job_id}.
api_router.include_router(reports.router)
