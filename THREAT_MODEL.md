# EPDN threat model

Status terms:

- **Prevented** — the specified protocol path rejects the attempt when its
  stated assumptions hold.
- **Detected** — the attempt is auditable but may have had limited effect.
- **Mitigated** — controls reduce probability or impact without eliminating it.
- **Out of scope** — the MVP cannot make a credible guarantee.

The evidence column is a release gate. A control without a passing test is a
design claim, not a verified result.

| # | Threat | Status | Control and residual risk | Required evidence |
|---:|---|---|---|---|
| 1 | Desktop app impersonates an ESP32 | Mitigated | Registry certificate plus proof-of-possession blocks an unprovisioned process. A copied L0/L1 key can still impersonate; strong resistance requires verified non-exportable L2/L3/L4 keys. | unregistered-client test |
| 2 | Copied device certificate | Prevented | A certificate alone is insufficient; the submission signature must verify under its public key. | certificate-without-key test |
| 3 | Certificate used without private key | Prevented | Domain-separated submission signature verification fails closed. | invalid-signature test |
| 4 | Flash image copied to another board | Mitigated | Firmware does not contain wallet keys. Clone resistance depends on a non-exportable device backend and boot policy; L1 images are not universally clone-proof. | backend capability report |
| 5 | Multiple tickets in one epoch | Prevented | Validator records `(epoch, device_public_key_hash)` before acceptance and returns a specific duplicate error. | duplicate test |
| 6 | Old ticket replay | Prevented | Epoch, previous hash, randomness, chain ID, and accepted-device set are validated. | replay test |
| 7 | Wrong chain ID | Prevented | Chain ID is inside the signed, hashed canonical challenge. | wrong-chain test |
| 8 | Wrong epoch | Prevented | Only the validator's current submission window is accepted. | old/future epoch tests |
| 9 | Wrong firmware ID | Prevented | Certificate firmware policy and current allowlist are checked. | firmware-policy test |
| 10 | L0 joins production | Prevented | Production build/config and validator policy both reject L0. | build-fail and API tests |
| 11 | Gateway changes a message | Prevented | Gateway transports an end-to-end signed bounded envelope and has no miner key. | tamper test |
| 12 | Revoked device rejoins | Prevented | Registry and cached revocation state are checked before ticket acceptance. | revoke-then-submit test |
| 13 | Device inflates security class | Prevented | Certificate-authorized class is authoritative; the submitted class must match exactly. | downgrade/inflation test |
| 14 | Oversized packet | Prevented | HTTP, UART, envelope, and field limits are enforced before allocation or parse. | boundary tests |
| 15 | Malformed deterministic encoding | Prevented | Parser rejects non-canonical, trailing, truncated, and out-of-range input. | parser tests and fuzz corpus |
| 16 | Randomness manipulation | Mitigated | Testnet commit-reveal combines validator inputs deterministically. Withholding policy and penalties are necessary; one-validator development randomness is insecure. | three-validator test |
| 17 | Validator equivocation | Detected | Signed commitments, reveals, blocks, and peer comparison create evidence. The MVP does not provide full Byzantine finality. | conflicting-vote test |
| 18 | Wallet XSS | Mitigated | Strict CSP, no unsafe HTML, dependency pinning, encrypted storage, short unlock lifetime, and no remote telemetry reduce risk. An unlocked browser can still be compromised. | CSP and storage tests |
| 19 | Clipboard address replacement | Mitigated | The confirmation view displays the complete address and QR-derived network before signing. Clipboard integrity cannot be guaranteed. | confirmation UI test |
| 20 | Malicious QR code | Mitigated | Parser bounds length, validates scheme/network/checksum, and requires explicit confirmation. | QR parser tests |
| 21 | Seed phrase leakage | Prevented in MVP | The MVP does not implement a mnemonic. It exports only a password-encrypted key file. | network/storage leak tests |
| 22 | Wi-Fi credential leakage | Mitigated | Masked serial input, ignored local secret files, generated headers, redacted logging, CI pattern checks, and no telemetry. A compromised host/device remains a risk. | secret-scan test |

## Trust anchors

Accepted roots of trust are provisioning-authority signatures and possession of
an enrolled device private key. MAC addresses, model registers, CPU frequency,
ADC noise, reset reason, timing, cache behavior, RSSI, and asserted serial
numbers are diagnostic data only.

## Sybil and provisioning boundary

“One ticket per device” is enforced as one accepted ticket per registered public
key per epoch. It does not stop a compromised authority from issuing many
identities. Production use therefore requires offline roots, controlled
intermediates, HSM-backed issuance, operator separation, inventory attestation,
audit records, certificate expiry, and revocation.

## Availability and network partitions

The MVP is fail-closed for invalid identity and protocol data, but it cannot
guarantee availability. Clock drift, partitions, denial of service, validator
crashes, or missing randomness reveals can delay finalization. Arrival order is
not a winner input; deterministic score and tie-break fields are.
