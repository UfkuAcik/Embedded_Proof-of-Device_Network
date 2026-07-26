from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from epdn_indexer.service import IndexerService
from epdn_indexer.store import IndexerStore

from .test_store import block


class FakeClient:
    def __init__(self, blocks: list[dict[str, Any]]) -> None:
        self.snapshot = blocks

    def status(self) -> dict[str, Any]:
        return {
            "protocol_version": 1,
            "chain_id": "epdn-local-testnet-v1",
            "height": len(self.snapshot),
        }

    def blocks(self) -> list[dict[str, Any]]:
        return self.snapshot


def test_rescan_is_rebuildable(tmp_path: Path) -> None:
    first = block(1, 11, 0, 1)
    client = FakeClient([first])
    with IndexerStore(tmp_path / "index.sqlite3") as store:
        service = IndexerService(client, store)  # type: ignore[arg-type]
        assert service.sync()["summary"]["tip"] == 1
        client.snapshot.append(
            block(
                2,
                12,
                first["block_hash"],  # type: ignore[arg-type]
                2,
            )
        )
        assert service.rescan()["summary"]["tip"] == 2
        assert store.summary()["blocks"] == 2


def test_failed_rescan_preserves_existing_projection(tmp_path: Path) -> None:
    client = FakeClient([block(1, 11, 0, 1)])
    with IndexerStore(tmp_path / "index.sqlite3") as store:
        service = IndexerService(client, store)  # type: ignore[arg-type]
        service.sync()

        def fail_blocks() -> list[dict[str, Any]]:
            raise RuntimeError("node unavailable")

        client.blocks = fail_blocks  # type: ignore[method-assign]
        with pytest.raises(RuntimeError, match="node unavailable"):
            service.rescan()
        assert store.summary()["blocks"] == 1
