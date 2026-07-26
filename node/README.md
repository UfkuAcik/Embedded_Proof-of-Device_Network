# EPDN Node

`epdn-node` is the single-validator local-testnet MVP. It binds to
`127.0.0.1:8745` by default, uses a validator-authenticated, checksummed atomic
state snapshot, and marks its single-node epoch randomness as insecure
development randomness.

Run locally:

```powershell
$env:EPDN_ADMIN_TOKEN = "<a long local token>"
cargo run -p epdn-node
```

If `EPDN_ADMIN_TOKEN` is omitted, the documented development token
`epdn-local-admin-change-me` is accepted only while binding to loopback. A
non-loopback bind fails unless the token is explicitly configured.

Optional variables:

- `EPDN_BIND_ADDR`
- `EPDN_CORS_ORIGINS` (comma-separated exact origins; wildcard is rejected)
- `EPDN_STATE_PATH`
- `EPDN_DEV_CA_PRIVATE_KEY_HEX`
- `EPDN_VALIDATOR_PRIVATE_KEY_HEX`
- `RUST_LOG`

The private-key variables contain 32-byte P-256 scalars in hex and are never
logged. Without them, deterministic keys are derived for local development and
are explicitly logged as insecure. A non-loopback bind requires both variables,
requires distinct keys, and never falls back to deterministic signing keys.

Loopback mode allows only `http://localhost:3000` and
`http://127.0.0.1:3000` by default. A non-loopback bind requires an explicit
`EPDN_CORS_ORIGINS` allowlist as well as an admin token containing at least 32
bytes.

## State snapshot format and migration

The local snapshot uses authenticated record format V3:

```text
"EPSJ" ||
record_version:u16_be (=3) ||
payload_length:u32_be ||
SHA256("EPDN_STATE_RECORD_CHECKSUM_V3" || payload) ||
validator_id:32 ||
validator_signature_p256_raw_rs:64 ||
payload
```

The validator signature covers the magic, version, length, checksum, validator
ID, and payload under the `EPDN_STATE_RECORD_SIGNATURE_V3` domain. Loading
requires the configured validator public key; a snapshot copied from another
validator, modified with a recomputed checksum, or signed by no validator is
rejected.

The payload is a storage-only DTO encoded with fixed-width, big-endian bincode.
Maps and sets are ordered collections, and transaction variants have an
explicit storage enum independent from the internally tagged REST JSON enum.
Changing a stored field, enum order, or encoding option requires a new record
version and an explicit migration. Snapshot bytes are local recovery data and
never enter a consensus hash.

Loading is fail-closed for unknown versions, oversized or truncated records,
checksum/signature failure, invalid payloads, and trailing bytes. Each
successful save writes and synchronizes a temporary file, then atomically
replaces the previous snapshot. Unsigned V1 and V2 files are deliberately
rejected; for this clean-root testnet, stop the node and archive/remove the old
file or select a new `EPDN_STATE_PATH`.

V3 records each device's first committed block height. Startup replays
registrations and finalized revocations, verifies both registry roots in every
block, checks the final registry in both directions, and reconstructs the
current `TicketPool` from its signed submissions before accepting the snapshot.

## API

Public:

- `GET /healthz`
- `GET /metrics`
- `GET /api/v1/network/status`
- `GET /api/v1/epochs/current`
- `GET /api/v1/epochs/{epoch}`
- `GET /api/v1/epochs/current/{device_public_id}/{firmware_id}`
- `GET /api/v1/events`
- `POST /api/v1/tickets`
- `POST /api/v1/transactions`
- `GET /api/v1/transactions/{hash}`
- `GET /api/v1/blocks`
- `GET /api/v1/blocks/{height_or_hash}`
- `GET /api/v1/address/{address}`
- `GET /api/v1/address/{address}/transactions`
- `GET /api/v1/miners`
- `GET /api/v1/miners/{public_id}`
- `GET /api/v1/miners/{public_id}/stats`
- `GET /api/v1/miners/{public_id}/rewards`

Admin-token protected:

- `POST /api/v1/admin/enroll`
- `POST /api/v1/admin/register`
- `POST /api/v1/admin/miners/{public_id}/revoke`
- `POST /api/v1/admin/epochs/finalize`
- `POST /api/v1/miners/{public_id}/commands`

Admin requests carry `x-epdn-admin-token`. The commands endpoint accepts
`pause`, `resume`, and `revoke`; revoke also requires a reason.

Accepted transfers reserve sequential nonces immediately, but finalized account
balances change only when the transaction is committed to a block. API state is
published in memory only after its complete snapshot has been persisted.

If every accepted ticket belongs to a device pending revocation, the validator
can finalize a rewardless revocation-only management block instead of
deadlocking. Such a block uses the all-zero winner marker, contains only one or
more revocation transactions, emits no reward event, and remains covered by the
normal validator block signature and registry-root checks.

The gateway never receives or creates a device private key. It obtains canonical
challenge bytes from the device-specific current-epoch endpoint and transports
the device-signed submission back to `POST /api/v1/tickets`. Ticket and transfer
bodies may be raw EPDN binary (`application/octet-stream`) or JSON envelopes
containing `submission_hex` / `transaction_hex`. JSON never enters a consensus
hash.

Stable rejection codes include `duplicate_device_epoch`, `duplicate_ticket`,
`duplicate_submission`, `stale_epoch_replay`, `revoked_device`,
`unregistered_device`, `wrong_network`, `wrong_nonce`, `transaction_replay`,
`insufficient_balance`, and `invalid_signature`.

SSE emits at least `ticket_accepted`, `new_block`, `reward`, `new_epoch`,
`certificate_revocation_queued`, and `certificate_revoked`. Public miner and
explorer responses deliberately omit SSID, IP address, MAC address, precise
location, private labels, and provisioning secrets.
