# EPDN deterministic binary encoding V1

This document is normative for consensus hashes in protocol version 1. JSON is
an API transport only and MUST NOT be hashed as a consensus object.

## Primitive encoding

- Integer byte order: unsigned, big-endian.
- `u8`, `u16`, `u32`, and `u64`: fixed-width.
- Fixed bytes: exactly the stated number of bytes, without a prefix.
- Short byte strings and UTF-8 strings: `u16 length || bytes`.
- Nested consensus objects: `u32 length || canonical object bytes`.
- Every top-level object starts with `45 50 44 4e` (`EPDN`), a one-byte object
  type, and a two-byte protocol version.
- Parsers reject unknown versions, invalid UTF-8, out-of-range lengths,
  invalid enum values, non-canonical ordering, truncation, and trailing bytes.
- Hash concatenations contain no implicit separators. Domain strings and
  fixed/length-delimited fields make every boundary explicit.

Object type assignments:

| Type | Object |
| ---: | --- |
| `1` | Epoch challenge |
| `2` | Device certificate payload |
| `3` | Signed device certificate |
| `4` | Ticket submission |
| `5` | Block header |
| `6` | Signed wallet transfer |
| `7` | Device revocation transaction |
| `8` | Reward distribution transaction |

Transaction discriminants are versioned independently: Transfer `1`, Device
Registration `2`, Device Certificate Update `3`, Device Revocation `4`,
Firmware Policy Update `5`, Validator Update `6`, Reward Distribution `7`, and
Miner Reward Address Update `8`. V1 executes Transfer, Device Revocation, and
Reward Distribution. Unsupported transaction kinds fail closed.

## Cryptographic profile

- Hash: SHA-256.
- Identity, certificate, ticket, validator, and wallet signature curve:
  NIST P-256.
- Public key: exactly 33-byte canonical compressed SEC1, prefix `02` or `03`.
- Signature: exactly 64 bytes, `r` then `s`, each a 32-byte big-endian integer.
  DER signatures are not accepted on the wire.
- Honest P-256 signers use RFC 6979 deterministic signing as implemented by the
  maintained RustCrypto `p256` crate. Consensus does not rely on a verifier
  being able to prove the signer's nonce-generation procedure. No EPDN
  cryptographic primitive is handwritten.

Certificate, ticket proof, ticket submission, and block signing functions first
produce an explicitly domain-separated 32-byte digest. That digest is passed
directly to P-256 ECDSA through a prehash API; implementations MUST NOT hash it
again.

Wallet transfer signing is intentionally Web Crypto compatible. The signed
input is the raw byte string:

```text
"EPDN_TRANSFER_SIGNATURE_V1" || unsigned_transfer_canonical_bytes
```

The normal ECDSA-with-SHA-256 API hashes this raw input exactly once. Web Crypto
clients use `ECDSA` with `hash: "SHA-256"` over the same raw bytes.

## Epoch challenge

```text
"EPDN" || type=1 || protocol_version:u16
chain_id:utf8-u16                    (maximum 64 bytes)
epoch_number:u64
previous_block_hash:[32]
network_randomness:[32]
device_public_key_hash:[32]
approved_firmware_id:[32]
security_class:u8                    (0..4)
```

The device public key hash is:

```text
SHA256("EPDN_DEVICE_PUBLIC_KEY_V1" || compressed_sec1_public_key)
```

## Device certificate payload

```text
"EPDN" || type=2 || protocol_version:u16
serial:[16]
device_public_key_sec1_compressed:[33]
platform:utf8-u16                    (maximum 32 bytes)
board_family:utf8-u16                (maximum 48 bytes)
security_class:u8
authority_id:[32]
provisioned_at_unix_seconds:u64
issued_at_epoch:u64
expires_at_epoch:u64                 (exclusive)
allowed_chain_id:utf8-u16            (maximum 64 bytes)
chip_revision:optional-string
batch_id:optional-string
manufacturer:optional-string
firmware_count:u16                   (maximum 16)
firmware_id:[32] * firmware_count
```

An optional string is `present:u8`; `0` has no following bytes and `1` is
followed by the usual `u16 length || UTF-8 bytes`. `Some("")` is non-canonical;
use the absent representation. Limits are 32 bytes for chip revision and 64
bytes each for batch ID and manufacturer. Firmware IDs MUST be strictly
ascending and duplicate-free.

The authority identifier and certificate signature digest are:

```text
authority_id =
  SHA256("EPDN_AUTHORITY_ID_V1" || authority_public_key_sec1_compressed)

certificate_digest =
  SHA256("EPDN_CERT_SIGNATURE_V1" || certificate_payload_bytes)
```

The signed certificate is:

```text
"EPDN" || type=3 || protocol_version:u16
payload_length:u32 || payload
signature_length:u16 (=64) || signature_raw_r_s
```

## Ticket

Given canonical `ticket_input = epoch_challenge_bytes`:

```text
proof_digest =
  SHA256("EPDN_PROOF_V1" || ticket_input)

deterministic_proof =
  P256_RFC6979_SIGN_PREHASH(device_key, proof_digest)

ticket =
  SHA256(
    "EPDN_TICKET_V1" ||
    device_public_key_hash ||
    ticket_input
  )

submission_hash =
  SHA256("EPDN_SUBMISSION_V1" || ticket_input || ticket)

submission_signature =
  P256_RFC6979_SIGN_PREHASH(device_key, submission_hash)

score =
  SHA256("EPDN_SCORE_V1" || ticket)
```

The proof authenticates possession of the certified device key, but proof
signature bytes MUST NOT enter `ticket` or `score`. ECDSA verification proves
signature validity; it cannot prove that the signer used RFC 6979 or any other
particular nonce-generation procedure. If signature bytes affected
eligibility, a malicious provisioned key holder could create multiple valid
signatures locally and retain the best score. With the V1 formula above, every
registered device public key has exactly one ticket for a fixed canonical
challenge, even when multiple distinct ECDSA proofs verify.

Submission layout:

```text
"EPDN" || type=4 || protocol_version:u16
challenge_length:u32 || challenge
proof_length:u16 (=64) || deterministic_proof
ticket:[32]
signature_length:u16 (=64) || submission_signature
```

The lowest score wins. Ties are broken by device public-key hash and then
submission hash, both in ascending byte order. Arrival order is never a
tiebreaker.

## Wallet transfer

Unsigned layout:

```text
"EPDN" || type=6 || protocol_version:u16
transaction_kind:u8 (=1)
chain_id:utf8-u16
sender_public_key_sec1_compressed:[33]
sender_address:[32]
recipient_address:[32]
amount:u64
fee:u64
nonce:u64
```

The signed layout appends `signature_length:u16 (=64) || signature_raw_r_s`.
The sender address is
`SHA256("EPDN_WALLET_ADDRESS_V1" || sender_public_key)`. Amount must be nonzero.
Nonce must equal the account's exact next nonce, starting at zero.

## Bounds and vectors

- Epoch challenge: at most 512 bytes.
- Device certificate: at most 4096 bytes.
- Ticket submission: at most 8192 bytes.
- Wallet transfer: at most 2048 bytes.
- Revocation reason: at most 128 UTF-8 bytes.

[`../test-vectors/v1.json`](../test-vectors/v1.json) fixes the cross-platform
certificate, ticket, and wallet-transfer bytes and hashes. Its private keys are
public test fixtures and MUST NOT be reused.
