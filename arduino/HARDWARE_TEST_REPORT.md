# EPDN ESP32 hardware test report

## Hardware identity

- Target family: classic ESP32
- Transport: local USB/UART
- Compile/upload target: `esp32:esp32:esp32`
- Exact board, chip revision, port, bridge, flash geometry, and unique
  identifiers: intentionally omitted
- Identity: development-only test identity; public identifiers and certificate
  bytes omitted

No irreversible security setting was changed. The target's security posture is
not published and this report makes no production hardware-assurance claim.

## Verified physical UART gateway flow

The final proof-exclusion `GatewayMiner` build was uploaded successfully. The
gateway relayed bytes only; the ESP32 created the RFC6979 P-256 proof and
submission signature.
ECDSA proof bytes are verified but excluded from ticket eligibility, preventing
a provisioned signer from grinding ECDSA nonces for a better score.

The physical `ProtocolTestVectors` run passed every non-secret stage:
`decode`, `identity_begin`, `build`, `ticket_match`,
`submission_length_match`, and `submission_match`.

1. An unregistered auxiliary participant was rejected with HTTP 404
   `unregistered_device`.
2. The same physical certificate was registered in a fresh local validator
   without resetting device NVS.
3. After advancing safely to epoch 6, the physical ESP32 received a 167-byte
   challenge, returned a 342-byte signed submission, and the node accepted it
   with HTTP 200.
4. Repeating the exact canonical challenge in the same boot returned the exact
   cached submission bytes. The cache is RAM-only and made no extra NVS write.
   A different challenge for the reserved epoch remained fail-closed.
5. Resubmitting the identical bytes returned HTTP 409
   `duplicate_submission`.
6. Finalization produced block height 6 for epoch 6. The physical device won,
   received 100 test tokens, the wallet balance became 100, and miner stats
   reported one block won.
7. A valid epoch 7 submission was captured before revocation. Revocation returned
   HTTP 204 and registry state became revoked. Submitting those otherwise valid
   signed bytes afterward returned HTTP 403 `revoked_device`.
8. The actual non-empty node process was stopped and restarted on the same
   EPSJ version 2 journal. Health returned HTTP 200 after restart, and height 6,
   epoch 7, wallet balance 100, and revoked state all persisted.
9. The local CORS policy allowed the configured localhost origin exactly.

An earlier proof-inclusive experiment was superseded by the nonce-grinding
hardening change and is not used as final protocol evidence.

The ignored V1 journal artifact was kept only as obsolete evidence; it was not
deleted, silently converted, or presented as compatible with the then-current
V2 or the current validator-authenticated V3 format.

## Not verified

- Direct Wi-Fi E2E was not exercised and no Wi-Fi credential was included.
- Signed EPSJ V3 restart is covered by automated tests but was introduced after
  this physical run and has not yet been repeated with hardware attached.
- Production hardware-backed identity and platform-attestation claims remain
  unverified.
- No target outside the classic ESP32 family has been physically tested.
