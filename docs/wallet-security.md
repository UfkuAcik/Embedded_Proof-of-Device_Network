# Wallet security

The EPDN Wallet is non-custodial. It creates and uses the wallet key inside the
browser and sends only public keys, addresses, and transaction signatures.

## MVP key storage

- Web Crypto generates a standard signing key.
- Private material is exported only transiently for encryption.
- PBKDF2-HMAC-SHA-256 derives an AES-GCM key from the user's password with a
  unique random salt and a versioned work factor.
- IndexedDB stores only the encrypted envelope, salt, IV, KDF parameters,
  public key, and format version.
- Export/import uses the same encrypted key-file envelope.
- Lock and inactivity timeout release all reachable plaintext key references.

The MVP deliberately omits mnemonic phrases rather than publish a partial or
non-standard seed scheme.

## Forbidden destinations

Private keys and plaintext recovery material must never be stored in
`localStorage`, cookies, plaintext IndexedDB, logs, telemetry, source control,
miner firmware, the node, or the indexer. Tests inspect storage writes and
network payloads for these fields.

## Residual risks

Encryption at rest does not protect an unlocked wallet from XSS, a malicious
extension, a compromised dependency, screen capture, or a compromised operating
system. Users must verify the full address, network, amount, and fee immediately
before signing.
