# EPDN protocol boundary

EPDN uses versioned deterministic binary objects for every value that enters a
hash or signature. REST JSON and SSE are transport/presentation formats only.
The byte-level V1 field order, bounds, integer widths, signature profiles, and
published cross-language vector are defined in:

- [`protocol/specification/encoding-v1.md`](protocol/specification/encoding-v1.md)
- [`protocol/test-vectors/v1.json`](protocol/test-vectors/v1.json)
- [`docs/consensus.md`](docs/consensus.md)

## Identity and wallet separation

A device identity key proves that a provisioned miner may submit a ticket. A
wallet key authorizes token transfers. Miner firmware receives only a public
reward address; it must never receive the wallet private key.

The present physical ESP32 development identity is L0 software-backed and is
valid only on development/testnet policy. Registration and a certificate do not
make an exportable key physically unclonable. Production anti-clone claims
require a verified non-exportable L2/L3 backend and hardened provisioning.

## Consensus objects

The V1 protocol implements:

- epoch challenge with chain, previous block, network randomness, device,
  firmware, and security-class binding;
- device-key proof and separately signed ticket submission;
- unique ticket derivation from device public-key hash and canonical challenge,
  deliberately excluding variable ECDSA proof bytes;
- score `SHA256("EPDN_SCORE_V1" || ticket)`;
- deterministic ordering by score, device public-key hash, then submission hash;
- device certificates, registry roots, firmware policy, and revocation roots;
- canonical blocks, validator signatures, transfers, rewards, and device
  revocations.

Every accepted identity may contribute at most one ticket to one validator's
epoch state. This is not a universal physical-device detector: a compromised
provisioning authority can create Sybil identities, and an exported identity
key can be cloned. Validators must therefore share registry/revocation state
and a finality protocol before production use.

## Cryptographic profiles

P-256 keys use compressed 33-byte SEC1 public keys. Signatures are fixed-width
64-byte big-endian `r || s`, never variable-width DER.

Certificate and ticket paths use their documented SHA-256 prehash profiles.
Wallet transfers sign
`"EPDN_TRANSFER_SIGNATURE_V1" || unsigned_canonical_transfer` with Web
Crypto-compatible ECDSA/SHA-256. Wallet addresses are the full 32-byte digest:

```text
SHA256("EPDN_WALLET_ADDRESS_V1" || compressed_wallet_public_key)
```

Cryptographic primitives come from maintained platform/library
implementations; the repository does not implement elliptic-curve arithmetic
or SHA-256.

## Unique-ticket derivation

For canonical challenge bytes `ticket_input`, V1 derives:

```text
ticket =
  SHA256(
    "EPDN_TICKET_V1" ||
    device_public_key_hash ||
    ticket_input
  )
```

The separately verified P-256 proof establishes possession of the provisioned
private key, but its signature bytes do not affect `ticket`, `submission_hash`,
or `score`. This separation is security-critical. ECDSA verification cannot
prove that a signer used RFC6979; a malicious private-key holder can construct
multiple distinct valid signatures for one message. Excluding those bytes
ensures every registered key has one eligibility value for a fixed challenge
and removes signature-nonce grinding.

The regression test
`proof_signature_variants_cannot_grind_ticket_or_score` constructs two distinct
valid ECDSA proofs for the same key/challenge, verifies both, and requires equal
ticket, submission hash, and score.

## Versioning rule

Unknown object types, protocol versions, enum values, trailing bytes,
non-canonical lengths, malformed keys/signatures, and oversized packets fail
closed. A future protocol version must publish new test vectors and must not
reinterpret V1 bytes.
