# EPDN Indexer

The indexer is a disposable SQLite read model for public finalized node data.
The validator remains the source of truth. No private key, Wi-Fi field,
provisioning credential, private miner alias, IP address, or MAC address belongs
in its schema or export.
The MVP consumes the node's full block snapshot from height 1; it does not yet
implement pagination or trusted checkpoints.

Install and synchronize:

```bash
python -m pip install -e "./indexer"
epdn-indexer --node-url http://127.0.0.1:8745 sync
epdn-indexer status
epdn-indexer export --output .epdn/public-index.json
```

`rescan` discards every derived row and rebuilds from `GET /api/v1/blocks`.
When a known height has a different block hash, `sync` removes that height and
all descendants before rebuilding balances, rewards, and transaction indexes.
The replacement snapshot is fetched first and applied transactionally, so a
failed fetch or invalid snapshot does not erase the last readable projection.
Numeric fields are bounded to SQLite's signed 64-bit range; an out-of-range
snapshot is rejected rather than truncated.

Before mutating SQLite, the indexer recomputes canonical transaction hashes,
transaction ordering, the Merkle root, and the block-header hash. It rejects
unknown transaction kinds, invalid transfer public-key/address bindings or
signatures, malformed revocations, and height/epoch mismatches. Validator
signature bytes are structurally checked, but their authenticity remains a
trust boundary: the public block API does not currently publish the configured
validator public key. Operators must therefore fetch snapshots over an
authenticated channel or establish a trusted validator-key checkpoint before
treating an export as independently authenticated.

Validator-signed revocation-only management blocks use the protocol's all-zero
winner marker, contain one or more revocation transactions, and create no reward
row or balance credit. Any partial marker, mixed transaction set, or synthetic
zero-address reward is rejected.

The node does not currently publish an absolute timestamp in a block header.
Hourly/day statistics therefore use deterministic epoch windows (120 and 2,880
epochs at the 30-second schedule). Pass a trusted `--genesis-unix` only when an
operator has established that time basis; otherwise the export leaves calendar
timestamps unset rather than inventing them.

This MVP provides CLI JSON export rather than a second public HTTP service. The
dashboard can continue reading the node directly, while analytics consumers can
read the atomic export. A continuously served query API and SSE-driven
incremental ingestion remain hardening work.
