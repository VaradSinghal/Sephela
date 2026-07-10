"""Custom checkpointer for LangGraph pipeline persistence."""

from __future__ import annotations

import json
import asyncio
from typing import Any, Dict, List, Optional, AsyncIterator
from dataclasses import dataclass, field
from datetime import datetime
from abc import ABC, abstractmethod

from langgraph.checkpoint.base import BaseCheckpointSaver, Checkpoint, CheckpointMetadata, CheckpointTuple


@dataclass
class PipelineCheckpoint:
    """Checkpoint data for pipeline persistence."""
    job_id: str
    sample_sha256: str
    step: int
    state: Dict[str, Any]
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.utcnow)


class PostgresCheckpointer(BaseCheckpointSaver):
    """PostgreSQL-backed checkpointer for production use."""
    
    def __init__(self, connection_string: str):
        self.connection_string = connection_string
        self._pool = None
    
    async def setup(self):
        """Initialize connection pool and create tables."""
        import asyncpg
        self._pool = await asyncpg.create_pool(self.connection_string)
        
        async with self._pool.acquire() as conn:
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS pipeline_checkpoints (
                    job_id UUID NOT NULL,
                    sample_sha256 CHAR(64) NOT NULL,
                    step INT NOT NULL,
                    state JSONB NOT NULL,
                    metadata JSONB DEFAULT '{}',
                    created_at TIMESTAMPTZ DEFAULT NOW(),
                    PRIMARY KEY (job_id, step)
                );
                CREATE INDEX IF NOT EXISTS idx_checkpoints_job ON pipeline_checkpoints(job_id);
            """)
    
    async def aput(self, config: Dict[str, Any], checkpoint: Checkpoint, metadata: CheckpointMetadata) -> None:
        """Save checkpoint asynchronously."""
        if not self._pool:
            await self.setup()
            
        job_id = config.get("configurable", {}).get("job_id", "unknown")
        sample_sha256 = config.get("configurable", {}).get("sample_sha256", "unknown")
        step = metadata.get("step", 0)
        
        async with self._pool.acquire() as conn:
            await conn.execute("""
                INSERT INTO pipeline_checkpoints (job_id, sample_sha256, step, state, metadata)
                VALUES ($1, $2, $3, $4, $5)
                ON CONFLICT (job_id, step) DO UPDATE SET
                    state = EXCLUDED.state,
                    metadata = EXCLUDED.metadata,
                    created_at = NOW()
            """, job_id, sample_sha256, step, json.dumps(checkpoint), json.dumps(metadata))
    
    async def aget_tuple(self, config: Dict[str, Any]) -> Optional[CheckpointTuple]:
        """Get checkpoint tuple asynchronously."""
        if not self._pool:
            await self.setup()
            
        job_id = config.get("configurable", {}).get("job_id")
        if not job_id:
            return None
            
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow("""
                SELECT state, metadata, created_at FROM pipeline_checkpoints
                WHERE job_id = $1
                ORDER BY step DESC
                LIMIT 1
            """, job_id)
            
            if not row:
                return None
                
            return CheckpointTuple(
                config=config,
                checkpoint=json.loads(row["state"]),
                metadata=json.loads(row["metadata"]),
                parent_config=None
            )
    
    async def alist(self, config: Dict[str, Any]) -> AsyncIterator[CheckpointTuple]:
        """List checkpoints asynchronously."""
        if not self._pool:
            await self.setup()
            
        job_id = config.get("configurable", {}).get("job_id")
        if not job_id:
            return
            
        async with self._pool.acquire() as conn:
            rows = await conn.fetch("""
                SELECT state, metadata, created_at FROM pipeline_checkpoints
                WHERE job_id = $1
                ORDER BY step DESC
            """, job_id)
            
            for row in rows:
                yield CheckpointTuple(
                    config=config,
                    checkpoint=json.loads(row["state"]),
                    metadata=json.loads(row["metadata"]),
                    parent_config=None
                )
    
    async def close(self):
        """Close connection pool."""
        if self._pool:
            await self._pool.close()


class InMemoryCheckpointer(BaseCheckpointSaver):
    """In-memory checkpointer for development/testing."""
    
    def __init__(self):
        self._checkpoints: Dict[str, List[PipelineCheckpoint]] = {}
    
    def put(self, config: Dict[str, Any], checkpoint: Checkpoint, metadata: CheckpointMetadata) -> None:
        job_id = config.get("configurable", {}).get("job_id", "unknown")
        sample_sha256 = config.get("configurable", {}).get("sample_sha256", "unknown")
        step = metadata.get("step", 0)
        
        if job_id not in self._checkpoints:
            self._checkpoints[job_id] = []
        
        cp = PipelineCheckpoint(
            job_id=job_id,
            sample_sha256=sample_sha256,
            step=step,
            state=checkpoint,
            metadata=metadata
        )
        self._checkpoints[job_id].append(cp)
    
    def get_tuple(self, config: Dict[str, Any]) -> Optional[CheckpointTuple]:
        job_id = config.get("configurable", {}).get("job_id")
        if not job_id or job_id not in self._checkpoints:
            return None
        
        latest = max(self._checkpoints[job_id], key=lambda c: c.step)
        return CheckpointTuple(
            config=config,
            checkpoint=latest.state,
            metadata=latest.metadata,
            parent_config=None
        )
    
    def list(self, config: Dict[str, Any]) -> List[CheckpointTuple]:
        job_id = config.get("configurable", {}).get("job_id")
        if not job_id or job_id not in self._checkpoints:
            return []
        
        return [
            CheckpointTuple(
                config=config,
                checkpoint=cp.state,
                metadata=cp.metadata,
                parent_config=None
            )
            for cp in sorted(self._checkpoints[job_id], key=lambda c: c.step, reverse=True)
        ]


def get_checkpointer(env: str = "development", connection_string: str = None) -> BaseCheckpointSaver:
    """Factory function to get appropriate checkpointer."""
    if env == "production":
        if not connection_string:
            raise ValueError("Connection string required for production checkpointer")
        return PostgresCheckpointer(connection_string)
    return InMemoryCheckpointer()