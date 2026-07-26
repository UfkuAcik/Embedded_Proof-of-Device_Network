"""Synchronize a rebuildable index from the validator's finalized view."""

from __future__ import annotations

from typing import Any

from .client import NodeClient
from .store import IndexerError, IndexerStore


class IndexerService:
    def __init__(self, client: NodeClient, store: IndexerStore) -> None:
        self.client = client
        self.store = store

    def sync(self, *, clear_existing: bool = False) -> dict[str, Any]:
        status = self.client.status()
        chain_id = status.get("chain_id")
        if not isinstance(chain_id, str) or not chain_id:
            raise IndexerError("node status did not contain a chain_id")
        blocks = self.client.blocks()
        result = self.store.replace_snapshot(
            blocks,
            expected_chain_id=chain_id,
            clear_existing=clear_existing,
        )
        return {"node": status, "index": result, "summary": self.store.summary()}

    def rescan(self) -> dict[str, Any]:
        return self.sync(clear_existing=True)
