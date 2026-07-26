# Embedded Proof-of-Device Network (EPDN)

EPDN is an experimental testnet in which a provisioned embedded-device identity
gets at most one deterministic ticket per epoch. `Proof of Provisioned Embedded
Device` (PoPED) selects the lowest deterministic score; it is not proof of work,
and faster CPUs, GPUs, FPGAs, or ASICs do not gain extra tickets by searching
nonces.

> **Safety:** this is an MVP for development and hardware research. It is not a
> production cryptocurrency, has no financial-return promise, and has not been
> independently audited.

## Repository status

A classic ESP32-family development target completed the physical UART test
flow. Public evidence records reproducible capabilities and outcomes, while
workstation details, port names, USB identifiers, exact device revisions, and
unique device data are intentionally excluded. Physical test evidence is
recorded separately from compile-only support.

The MVP is split into:

- **EPDN Node** — Rust validator, registry, epoch manager, PoPED validation,
  ledger, REST/SSE API, and local testnet utilities.
- **EPDN Miner** — Arduino library and sketches with platform capabilities,
  serial Wi-Fi provisioning, deterministic tickets, and bounded messages.
- **EPDN Provisioner** — host CLI for inspection, development enrollment,
  registration, flashing, monitoring, revocation, and security dry-runs.
- **EPDN Gateway** — untrusted UART relay for already-signed miner envelopes.
- **EPDN Wallet / Dashboard / Explorer** — responsive installable TypeScript PWA
  with an encrypted, non-custodial testnet wallet.

## Trust model in one sentence

A non-provisioned program does not possess a project-certified device private
key. This limits participation by registered identity, not by computing power.
The strength of “device” assurance still depends on the selected identity
backend and provisioning controls.

## Quick start

Prerequisites and exact commands are kept deterministic in the component
readmes and scripts:

```text
cargo test --workspace
python -m pip install -e "./provisioning[test]" -e "./gateway" -e "./indexer[test]"
python -m pytest -q provisioning/tests gateway/tests indexer/tests scripts/tests
arduino-cli compile --fqbn esp32:esp32:esp32 --libraries arduino/libraries arduino/examples/SecurityDiagnostic
epdn-provision inspect
cd dashboard && npm test
```

Use only development credentials on the local testnet. Wi-Fi credentials belong
in an ignored local secret or should be entered through the serial provisioning
prompt; they must never appear in commands, logs, source files, or build output.

Operational guides: [CI gates](docs/ci.md),
[local testnet and container](docs/local-testnet.md), and
[indexer/export](docs/indexer.md).

## Protocol summary

The consensus-critical representation is `EPDN Binary Encoding v1`, a fixed
field order with big-endian integers and bounded length-prefixed byte strings.
JSON is used only at API boundaries. Every hash has a domain-separation tag.
For an epoch, each registered device public-key hash can be accepted once.
Arrival order never participates in winner selection.

See [PROTOCOL.md](PROTOCOL.md), [THREAT_MODEL.md](THREAT_MODEL.md), and
[docs/architecture.md](docs/architecture.md).

## Physical safety

Normal diagnostic/miner firmware uploads overwrite the current application
image. The project does **not** burn eFuses, permanently enable secure boot or
flash encryption, disable JTAG/UART download, or increment anti-rollback values
without a separate explicit user decision.
