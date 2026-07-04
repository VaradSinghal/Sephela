"""Celery application — background task framework (Phase 2 foundation).

Queue topology mirrors docs/architecture/05-messaging.md: separate queues per
workload class so slow engines never starve fast ones. Only the wiring +
routing + a health task exist now; analysis tasks arrive in later phases.
"""

from __future__ import annotations

from celery import Celery
from kombu import Queue

from app.core.config import settings

celery_app = Celery(
    "sephela",
    broker=settings.redis_url,
    backend=settings.redis_url,
    include=["app.tasks.health"],
)

# Workload-class queues (workers subscribe to subsets of these per pool).
WORKLOAD_QUEUES = (
    "intake",
    "static",
    "code_intel",
    "ai",
    "dynamic",
    "threat_intel",
    "scoring",
    "reporting",
    "notify",
)

celery_app.conf.update(
    task_default_queue="intake",
    task_queues=tuple(Queue(name) for name in WORKLOAD_QUEUES),
    task_acks_late=True,                 # redeliver if a worker dies mid-task
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=1,        # backpressure for heavy tasks
    task_track_started=True,
    task_time_limit=30 * 60,             # hard limit (per-task overrides later)
    task_soft_time_limit=25 * 60,
    result_expires=60 * 60 * 24,
    timezone="UTC",
    enable_utc=True,
    broker_connection_retry_on_startup=True,
)
