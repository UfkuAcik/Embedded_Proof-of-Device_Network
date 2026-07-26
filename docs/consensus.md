# PoPED consensus and testnet status

Proof of Provisioned Embedded Device (PoPED) gives one registered device
identity one deterministic opportunity per epoch. It deliberately has no nonce
search loop, so additional CPU/GPU/FPGA/ASIC hash rate does not create more
tickets for the same identity.

## Epoch sequence

The default epoch is 30 seconds:

1. Ticket submission window: 20 seconds.
2. Finalization window: 10 seconds.
3. Validators reject a second ticket from the same registered identity.
4. The lowest score wins; ties use device public-key hash and submission hash.
5. Packet arrival order is never a tie-break input.
6. The block commits to the previous block, epoch randomness, winning ticket
   and submission hash, firmware/security policy, transactions, registry, and
   revocation state.

Validators reject stale/future epochs, wrong chain or previous hash, wrong
randomness/firmware, invalid or expired certificates, revocation, invalid
signatures/attestation, security downgrade, L0 production participation,
replay, duplicate, malformed, and oversized input.

### Unique-ticket invariant

V1 separates proof of key possession from eligibility:

```text
proof_digest = SHA256("EPDN_PROOF_V1" || canonical_challenge)
proof = P256_SIGN_PREHASH(device_key, proof_digest)

ticket =
  SHA256(
    "EPDN_TICKET_V1" ||
    device_public_key_hash ||
    canonical_challenge
  )
```

The validator verifies `proof`, but proof signature bytes do not enter the
ticket or score. This is necessary because an ECDSA verifier cannot prove that
the signer used RFC6979; a private-key holder can produce more than one valid
signature for the same message. Excluding the proof bytes makes all such
signatures map to the same ticket, submission hash, and score. The regression
test `proof_signature_variants_cannot_grind_ticket_or_score` enforces this
invariant using the high/low-S forms of one valid P-256 signature.

## Randomness

The single-node executable reports
`insecure_single_node_development` because one process derives development
randomness without independent contributors. It is useful for end-to-end
development, not production fairness.

`CommitRevealRound` implements deterministic multi-validator randomness:

- every configured validator commits before finalization;
- reveals are checked against commitments;
- final transcript order is validator-ID order, not network arrival order;
- a committed missing reveal contributes a domain-separated commitment marker;
- missing reveal identities are returned for policy/penalty handling.

The test
`three_validators_finalize_identically_in_any_arrival_order` proves that three
in-process validator views produce the same output under different arrival
orders. It does not prove Byzantine network finality.

## Current three-validator limit

`scripts/testnet.py` can launch three node API processes with distinct local
validator keys and state journals. The processes currently do not exchange
blocks, commitments, or votes over a P2P protocol. The smoke command therefore
checks:

- three healthy bounded-loopback APIs;
- the same protocol version, chain ID, and fresh height;
- the separate in-process three-validator commit/reveal agreement test.

It must not be reported as production peer synchronization or Byzantine
finality. Those remain hardening work.

## Security boundary

“One device per epoch” means one accepted registered identity in a validator's
consistent state. It depends on provisioning authority controls, non-exportable
keys where claimed, registry synchronization, revocation propagation, and
validator finality. MAC address, model registers, timing, RSSI, reset reason,
and other telemetry are never roots of trust.
