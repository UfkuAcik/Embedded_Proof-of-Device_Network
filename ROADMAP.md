# EPDN roadmap

## MVP

- Deterministic EPDN Binary Encoding v1 and shared Rust/Arduino test vectors.
- Single Rust validator with registry, certificate policy, revocation, PoPED
  ticket validation, block reward ledger, persistence, REST API, and SSE.
- ESP32 diagnostic and miner firmware with serial provisioning.
- Development CA/provisioning CLI and an untrusted UART gateway.
- Encrypted non-custodial PWA wallet, dashboard, and public explorer.
- Three-validator local testnet simulation with commit-reveal randomness.
- Negative, adversarial, secret-leak, and CI checks.

## Hardening after MVP

- Independent protocol and cryptography review.
- Verified ESP32 hardware identity backends by chip family; no silent fallback.
- ATECC608A/ECC508 integration and hardware-in-the-loop fixtures.
- Reproducible signed OTA, staged rollout, rollback recovery, and measured boot.
- Offline root CA, HSM-backed intermediate, dual control, batch audit records,
  renewal ceremonies, and emergency revocation operations.
- Byzantine peer synchronization and a production-grade finality protocol.
- Sustained fuzzing, power-loss fault injection, storage wear tests, and formal
  state-machine review.
- Native Android and iOS wallet applications after the PWA security model is
  independently reviewed.

## Non-goals

- Hash-rate mining or brute-force nonce search.
- Claims of universal emulator detection.
- Mainnet, exchange listing, investment returns, or assets of real value.
