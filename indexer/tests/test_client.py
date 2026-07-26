from __future__ import annotations

import pytest

from epdn_indexer.client import NodeClient


@pytest.mark.parametrize(
    "url",
    [
        "file:///tmp/node.json",
        "127.0.0.1:8745",
        "http://user:password@127.0.0.1:8745",
        "http://127.0.0.1:8745?token=test",
        "http://127.0.0.1:8745#fragment",
    ],
)
def test_node_client_rejects_unsafe_or_ambiguous_urls(url: str) -> None:
    with pytest.raises(ValueError):
        NodeClient(url)


def test_node_client_requires_positive_bounds() -> None:
    with pytest.raises(ValueError, match="timeout"):
        NodeClient("http://127.0.0.1:8745", timeout_seconds=0)
    with pytest.raises(ValueError, match="response size"):
        NodeClient("http://127.0.0.1:8745", maximum_response_bytes=0)
