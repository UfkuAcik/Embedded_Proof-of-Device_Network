# Architecture

EPDN separates device identity, reward ownership, consensus validation, query
indexing, and transport.

```text
EPDN Miner ── signed ticket ──► EPDN Node ── finalized blocks ──► Indexer
    │             ▲                  │                              │
    │             │                  ├── REST / SSE ────────────────┤
    └─ Wi-Fi or untrusted UART       │                              ▼
       Gateway (relay only)          └──────────────────────► Dashboard
                                                                      │
                                      locally encrypted wallet ◄──────┘
```

The miner holds only a device-identity key and a public reward address. The
wallet key never enters miner firmware, the validator, the gateway, the
indexer, logs, or telemetry.

## Consensus boundary

Consensus code owns:

- deterministic binary encoding and domain-separated hashes;
- certificate, registry, firmware, revocation, and security-class policy;
- one accepted ticket per device identity per epoch;
- deterministic score and tie-break selection;
- deterministic block/state transition and reward assignment.

REST JSON, SSE rendering, database indexes, dashboard charts, and packet arrival
order are outside the consensus hash boundary.

Transfers and revocations are validated and queued before finalization, but
they do not alter finalized ledger or registry state until their canonical
transactions enter a signed block. The block's convenience reward record must
match its single Merkle-committed reward transaction exactly. A node mutation
becomes visible in memory only after the corresponding
validator-authenticated, checksummed state snapshot has been persisted
successfully.

Protocol V1 amounts are unsigned, indivisible testnet units. Rewards, balances,
transfer amounts, and fees use the same raw `u64` scale; no decimal or
micro-unit conversion is defined.

## Identity backends

Every backend advertises a `SecurityClass` and capabilities. Selection is
explicit; unsupported production configurations fail closed.

- `L0_SOFTWARE_TEST` — desktop/emulator/test-only key.
- `L1_PROTECTED_SOFTWARE_IDENTITY` — software-accessible key in protected
  storage with platform hardening where verified.
- `L2_NATIVE_HARDWARE_IDENTITY` — non-exportable native device operation.
- `L3_EXTERNAL_SECURE_ELEMENT` — non-exportable secure-element key.
- `L4_ATTESTED_PLATFORM` — signed measurements and security state.

## Network modes

- `development` — one validator and explicitly insecure deterministic
  development randomness.
- `testnet` — three local validators with commit-reveal randomness and
  deterministic comparison.
- `production` — design target only; L0 disabled, multiple independent
  validators, hardened provisioning, audited firmware, and verified hardware
  backends are mandatory.

## Data ownership

The validator remains the source of truth. The indexer can be discarded and
rebuilt from finalized blocks. Dashboard aliases and display preferences are
private application data and never enter the public explorer.
