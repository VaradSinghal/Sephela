"""Checkpointer selection for the analysis graph.

APK analysis is long-running and agent calls are expensive, so a worker that dies
mid-job must be able to resume rather than re-run eight agents. That durability is
LangGraph's checkpointer contract — and it is a larger contract than it looks:
besides ``aget_tuple``/``aput`` a saver must implement ``aput_writes`` and the
channel-versioning hooks the graph engine calls between every node.

This module therefore *selects* a checkpointer rather than implementing one. A
hand-rolled saver that covers only the sync methods compiles and then fails at the
first node boundary with ``NotImplementedError`` from the base class, which is a
much worse failure than not having checkpointing at all.

    get_checkpointer("development")             → in-memory, per-process
    get_checkpointer("production", dsn)          → Postgres-backed, durable

The in-memory saver is per-process, so it gives resume-after-exception within a
worker but not resume-after-restart. Production must pass a DSN.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from langgraph.checkpoint.memory import MemorySaver

if TYPE_CHECKING:
    from langgraph.checkpoint.base import BaseCheckpointSaver

# Kept under the old name because callers (and ai.orchestration's public API)
# import it; it is LangGraph's saver, which implements the full async contract.
InMemoryCheckpointer = MemorySaver

_POSTGRES_INSTALL_HINT = (
    "Postgres checkpointing needs the optional dependency: "
    "pip install 'langgraph-checkpoint-postgres'"
)


def PostgresCheckpointer(connection_string: str) -> BaseCheckpointSaver:  # noqa: N802
    """Build a durable Postgres-backed checkpointer.

    Named as a class for backwards compatibility with the previous API — it is a
    factory because LangGraph's Postgres saver owns a connection pool that has to
    be created around the DSN rather than subclassed.

    The returned saver still needs ``await saver.setup()`` once per database to
    create its tables; that is a migration-time concern, not a per-job one.
    """
    try:
        from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver
    except ImportError as exc:  # pragma: no cover - depends on optional extra
        raise ImportError(_POSTGRES_INSTALL_HINT) from exc

    try:
        from psycopg_pool import AsyncConnectionPool
    except ImportError as exc:  # pragma: no cover - depends on optional extra
        raise ImportError(_POSTGRES_INSTALL_HINT) from exc

    # open=False so constructing the checkpointer does not perform I/O; the pool
    # opens lazily on first use, which keeps this factory callable from sync code.
    pool: Any = AsyncConnectionPool(
        conninfo=connection_string,
        max_size=10,
        open=False,
        kwargs={"autocommit": True, "row_factory": "dict_row"},
    )
    return AsyncPostgresSaver(pool)


def get_checkpointer(
    env: str = "development",
    connection_string: str | None = None,
) -> BaseCheckpointSaver:
    """Return the checkpointer appropriate to the environment.

    Args:
        env:               ``"production"`` selects the durable Postgres saver;
                           anything else selects the in-memory one.
        connection_string: Postgres DSN. Required for production — a production
                           worker that silently checkpointed to memory would lose
                           every in-flight job on restart, so this raises instead.
    """
    if env == "production":
        if not connection_string:
            raise ValueError(
                "Connection string required for the production checkpointer — "
                "in-memory checkpoints do not survive a worker restart."
            )
        return PostgresCheckpointer(connection_string)
    return MemorySaver()


__all__ = [
    "InMemoryCheckpointer",
    "MemorySaver",
    "PostgresCheckpointer",
    "get_checkpointer",
]
