"""Celery application — background task framework (Phase 2 foundation).

Queue topology mirrors docs/architecture/05-messaging.md: separate queues per
workload class so slow engines never starve fast ones. Only the wiring +
routing + a health task exist now; analysis tasks arrive in later phases.
"""

from __future__ import annotations

from celery import Celery
from celery.signals import worker_ready
from kombu import Queue

from app.core.config import settings

celery_app = Celery(
    "sephela",
    broker=settings.redis_url,
    backend=settings.redis_url,
    include=["app.tasks.health", "app.tasks.pipeline", "app.tasks.dynamic"],
)


@worker_ready.connect
def _start_metrics_exporter(**_kwargs: object) -> None:
    """Expose this worker's metrics once it is actually ready to work.

    On ``worker_ready`` rather than at import time: the module is imported by the API
    process too (to send tasks), and starting a listener there would collide with the
    API's own port and export a set of collectors nothing in that process increments.
    """
    from app.core.pipeline_metrics import setup_worker_metrics

    setup_worker_metrics()


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
    task_acks_late=True,  # redeliver if a worker dies mid-task
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=1,  # backpressure for heavy tasks
    task_track_started=True,
    task_time_limit=30 * 60,  # hard limit (per-task overrides later)
    task_soft_time_limit=25 * 60,
    result_expires=60 * 60 * 24,
    timezone="UTC",
    enable_utc=True,
    broker_connection_retry_on_startup=True,
    # Queue depth is the metric that says whether the workers are keeping up, and it can
    # only be read by asking the broker — no task emits it.
    beat_schedule={
        "publish-queue-depth": {
            "task": "health.publish_queue_depth",
            "schedule": float(settings.queue_depth_interval_secs),
            "options": {"queue": "notify", "expires": settings.queue_depth_interval_secs},
        }
    },
)
