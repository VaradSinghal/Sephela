"""Liveness tasks: a queue round-trip probe and the queue-depth gauge."""

from __future__ import annotations

from app.core.logging import get_logger
from app.tasks.celery_app import WORKLOAD_QUEUES, celery_app

logger = get_logger(__name__)


@celery_app.task(name="health.ping")
def ping() -> str:
    """Return 'pong' — smoke test for broker + worker connectivity."""
    return "pong"


@celery_app.task(name="health.publish_queue_depth", queue="notify")
def publish_queue_depth() -> dict[str, int]:
    """Publish how many messages are waiting on each workload queue.

    Queue depth is the metric that answers "are the workers keeping up", and nothing
    else can produce it: no task knows how many others are behind it, so the broker has
    to be asked. Run from beat rather than per message, because a gauge is sampled.

    Never raises. It is a monitoring probe, and a broker hiccup here must not put a
    retrying task on a queue whose depth it was supposed to be reporting.
    """
    from app.core.pipeline_metrics import set_queue_depth

    depths: dict[str, int] = {}
    try:
        with celery_app.connection_or_acquire() as connection:
            client = connection.default_channel.client
            for queue in WORKLOAD_QUEUES:
                # Celery's Redis transport stores each queue as a list keyed by name, so
                # its length is the backlog. Broker-specific by necessity — there is no
                # portable depth API in kombu.
                depths[queue] = int(client.llen(queue))
    except Exception as exc:  # noqa: BLE001 — see the docstring
        logger.warning("queue_depth_probe_failed", error=str(exc))
        return {}

    for queue, depth in depths.items():
        set_queue_depth(queue, depth)
    return depths
