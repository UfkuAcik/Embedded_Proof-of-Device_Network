# Protocol and node acceptance-test map

This file maps the acceptance requirements to executable Rust test names. Test
names are stable evidence labels; a passing test covers only the behavior its
assertions exercise.

Run the Rust acceptance suite from the repository root:

```text
cargo test --workspace --no-fail-fast
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

## Protocol and consensus requirements

| Requirement | Executable evidence |
| --- | --- |
| Canonical encoding | `challenge_encoding_is_deterministic_and_round_trips`; `challenge_rejects_trailing_and_oversized_data`; `ticket_is_deterministic_and_round_trips`; `p256_transfer_is_deterministic_and_round_trips`; `valid_fuzz_seeds_match_v1_vectors_and_round_trip_canonically` |
| Rust/shared test vectors | `rust_matches_the_checked_in_cross_platform_v1_vector`; `valid_fuzz_seeds_match_v1_vectors_and_round_trip_canonically` |
| Deterministic, non-grindable ticket | `ticket_is_deterministic_and_round_trips`; `proof_signature_variants_cannot_grind_ticket_or_score`; `rust_matches_the_checked_in_cross_platform_v1_vector` |
| Signature verification | `tampering_is_rejected`; `tampered_certificate_fails_closed`; `validator_signature_is_bound_to_block_hash`; `transfer_rejects_wrong_network_and_tampering` |
| Certificate verification and expiry | `signed_certificate_round_trips_and_verifies`; `tampered_certificate_fails_closed`; `certificate_expiry_is_epoch_bounded` |
| Duplicate device/ticket/submission rejection | `valid_ticket_is_accepted_and_exact_replay_is_rejected`; `second_ticket_from_same_device_is_rejected_even_before_bad_crypto` |
| Ticket replay rejection | `valid_ticket_is_accepted_and_exact_replay_is_rejected`; `stale_future_wrong_chain_and_wrong_randomness_are_rejected` |
| Revocation | `revoked_and_paused_devices_fail_closed`; `block_commits_reward_and_revocation_transactions`; `registry_and_revocation_roots_are_deterministic` |
| Firmware allowlist | `firmware_security_downgrade_and_unregistered_device_are_rejected` |
| Security downgrade/unregistered emulator | `firmware_security_downgrade_and_unregistered_device_are_rejected` |
| L0 production rejection | `production_rejects_l0_identity` |
| Wrong chain, epoch, parent, or randomness | `stale_future_wrong_chain_and_wrong_randomness_are_rejected` |
| Malformed and oversized packets | `challenge_rejects_trailing_and_oversized_data`; `parser_rejects_truncated_and_oversized_packets`; `malformed_and_oversized_consensus_packets_are_rejected`; `truncated_fuzz_seeds_are_rejected_by_every_consensus_parser` |
| Winner independent of arrival order | `winner_and_block_are_independent_of_ticket_arrival_order` |
| Deterministic block/reward/roots | `block_hash_and_reward_ledger_are_deterministic`; `block_commits_reward_and_revocation_transactions`; `merkle_root_is_order_sensitive_and_repeatable`; `registry_and_revocation_roots_are_deterministic` |
| Three-validator randomness | `three_validators_finalize_identically_in_any_arrival_order`; `missing_reveal_is_deterministic_and_reported` |

## Ledger, persistence, and API requirements

| Requirement | Executable evidence |
| --- | --- |
| Wallet transfer signature and canonical boundary | `p256_transfer_is_deterministic_and_round_trips`; `transfer_rejects_wrong_network_and_tampering`; fixed V1 vector |
| Nonce, fee, balance, replay, wrong-network rules | `reward_transfer_nonce_replay_network_and_balance_rules_are_enforced` |
| Failed transfer atomicity | `failed_transfer_does_not_partially_mutate_ledger` |
| Persistent-state truncated-tail recovery | `journal_recovers_last_complete_snapshot_and_ignores_truncated_tail` |
| Gateway-facing canonical challenge/binary transport | `admin_auth_gateway_challenge_duplicate_and_revocation_contract` |
| Stable duplicate/revocation API contract | `admin_auth_gateway_challenge_duplicate_and_revocation_contract` |
| Admin authentication and CORS | `admin_auth_gateway_challenge_duplicate_and_revocation_contract`; `wildcard_cors_configuration_is_rejected` |

## Fuzzing

The isolated `protocol/fuzz` crate contains libFuzzer targets for every
externally supplied consensus parser:

| Target | Parser | Seed corpus |
| --- | --- | --- |
| `epoch_challenge_decode` | `EpochChallenge::decode` | valid V1 challenge, truncated header |
| `device_certificate_decode` | `DeviceCertificate::decode` | valid V1 certificate, truncated header |
| `ticket_submission_decode` | `TicketSubmission::decode` | valid V1 submission, truncated header |
| `signed_transfer_decode` | `SignedTransfer::decode` | valid V1 transfer, truncated header |

Each target feeds arbitrary bytes to its bounded decoder. Successful decodes
must re-encode byte-for-byte identically, so the target tests both panic safety
and canonical uniqueness. The regular workspace tests also compile-time include
and execute every seed, allowing corpus integrity to be checked on hosts where
libFuzzer is unavailable.

See [`fuzz/README.md`](fuzz/README.md) for nightly commands and host support.

## Cross-component and hardware requirements

These requirements cannot be proven by the Rust workspace alone and are not
silently counted as Rust coverage:

| Requirement | Evidence or current boundary |
| --- | --- |
| Arduino compatibility | `arduino/examples/ProtocolTestVectors/ProtocolTestVectors.ino` consumes the shared V1 values; it still requires an Arduino compile/run in the component or hardware workflow |
| Gateway tampering | Python gateway tests `test_uart_tamper_is_rejected`, `test_oversized_uart_payload_is_rejected`, and `test_relay_returns_device_bytes_without_mutation`; the node still performs final cryptographic verification |
| Provisioning failure/irreversible guard | Python provisioning tests `test_tampering_and_oversize_fail`, `test_production_requires_exact_guard`, and `test_confirmed_plan_still_never_writes` |
| Wallet encryption/private-key storage/network isolation | Dashboard tests `wallet keeps private material inside Web Crypto and encrypted IndexedDB` and `wallet create and unlock keep only ciphertext in IndexedDB` |
| Dashboard authorization | Dashboard test `write actions authenticate server-side and keep admin token server-only`; Rust API auth is covered separately above |
| NVS corruption, Wi-Fi reconnect, power interruption, OTA interruption | Device/hardware fault-injection tests; not demonstrated by the Rust suite |
| Wallet auto-lock | UI/session timer behavior; not demonstrated by the Rust suite |
| Seed phrase leakage | No mnemonic/seed-phrase feature is shipped in the MVP; encrypted key-file import/export is used instead |
| Explorer privacy | Response/UI contract test outside the Rust consensus suite |
| Indexer rescan and chain reorganization | No standalone indexer consensus claim; requires indexer integration tests |
| Full networked three-validator finalization and peer sync | Commit-reveal convergence is unit-tested, but independent node processes, peer sync, quorum finality, and reorganization are not implemented |
| Physical ESP32 ticket/duplicate/revocation/reward flow | Must be recorded as hardware evidence; compile-only or Rust simulation is not a physical pass |

This separation is intentional: parser and state-machine tests establish
software invariants, while hardware, browser, transport, and distributed-system
claims require their own execution evidence.
