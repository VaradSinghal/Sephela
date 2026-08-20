"""Local-filesystem storage backend (dev/local)."""

from __future__ import annotations

import asyncio
from pathlib import Path

from app.storage.base import StorageBackend


class LocalStorage(StorageBackend):
    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, key: str) -> Path:
        return self.root / key

    async def save(self, key: str, data: bytes) -> str:
        path = self._path(key)

        def _write() -> None:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)

        await asyncio.to_thread(_write)
        return self.uri_for(key)

    def uri_for(self, key: str) -> str:
        return f"file://{self._path(key).resolve()}"

    async def load(self, key: str) -> bytes:
        return await asyncio.to_thread(self._path(key).read_bytes)

    async def exists(self, key: str) -> bool:
        return await asyncio.to_thread(self._path(key).exists)

    async def delete(self, key: str) -> None:
        def _unlink() -> None:
            self._path(key).unlink(missing_ok=True)

        await asyncio.to_thread(_unlink)
