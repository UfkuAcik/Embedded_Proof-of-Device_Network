# Indexer operations

`indexer/` is a lightweight, disposable SQLite projection. It follows the
node's finalized `/api/v1/blocks` snapshot, detects a changed hash at a known
height, removes the divergent suffix, and rebuilds rewards, public transfers,
balances, and epoch-window statistics.
The current node endpoint returns a full snapshot; the indexer requires it to
begin at height 1 and link from the zero genesis hash. Pagination and
checkpoint-based ingestion are future work.

```bash
python -m pip install -e "./indexer"
epdn-indexer sync
epdn-indexer status
epdn-indexer export --output .epdn/public-index.json
epdn-indexer rescan
```

The export is written atomically and contains public chain IDs, hashes,
addresses, rewards, balances, and aggregate windows. It excludes raw API JSON
so a future node field cannot accidentally add SSID, IP, MAC, private aliases,
or provisioning data to the public artifact.

The node is always the source of truth. Deleting the SQLite database and
running `rescan` must recover the same projection. The MVP does not run a second
public HTTP server or pretend that an index is consensus state.

`rescan` fetches and parses the replacement snapshot before clearing rows, then
rebuilds inside one SQLite transaction. A transport or validation failure
therefore leaves the previous readable projection intact.

This SQLite MVP accepts non-negative chain integers through `2^63 - 1` and
rejects a snapshot whose values or derived balances exceed that storage range.
