# ESP32 hardware run

Target: classic ESP32-family development hardware reached through a local
USB/UART connection. Exact board, revision, flash geometry, port, bridge, and
unique identifiers are intentionally omitted.

The final end-to-end path used the UART gateway. The gateway relayed signed
bytes only: the physical target created the P-256 proof and submission
signature. The identity is development-only; its public identifier and
certificate bytes are omitted. This is testnet evidence, not production
hardware-backed identity evidence.

| Step | Result | Evidence / blocker |
|---|---|---|
| Detect serial transport | PASS | A local USB/UART transport was available |
| Detect target family | PASS | Read-only inspection identified a classic ESP32-family target |
| Avoid publishing a hardware fingerprint | PASS | Exact target, port, USB, driver, memory, and unique identifier values are omitted |
| Avoid irreversible security changes | PASS | The diagnostic flow performed no irreversible operation |
| Compile and upload diagnostic firmware | PASS | Upload verification completed using the repository's supported toolchain |
| Verify sanitized diagnostic output | PASS | [`results/esp32-diagnostic-sanitized.jsonl`](results/esp32-diagnostic-sanitized.jsonl) |
| Run cross-platform protocol vector | PASS | Physical `ProtocolTestVectors` passed decode, identity initialization, build, ticket, length, and submission byte checks |
| Create development identity | PASS | A development-only P-256 identity was initialized; identifiers are omitted |
| Install/register development certificate | PASS | Identity continuity was verified without publishing certificate bytes |
| Start local validator | PASS | A fresh local validator accepted the registered physical target |
| Reject an unregistered participant | PASS | Auxiliary unregistered participant received HTTP 404 `unregistered_device` |
| Submit physical proof and ticket | PASS | The target returned a signed submission and the node accepted it |
| Retry the same challenge | PASS | Same-boot retry returned byte-identical cached submission data without an extra persistent write |
| Reject duplicate submission | PASS | Resubmitting the identical signed bytes returned HTTP 409 `duplicate_submission` |
| Finalize block and reward | PASS | The physical target won the test epoch and received the expected test reward |
| Reject revoked device | PASS | A previously valid signed submission was rejected after revocation |
| Restart from non-empty signed V3 journal | NOT RUN | Historical unsigned V2 restart passed; V3 has automated coverage but was introduced after this physical run |
| Enforce configured CORS origin | PASS | The node allowed the configured localhost origin exactly |
| Provision Wi-Fi and run direct Wi-Fi E2E | NOT RUN | No Wi-Fi credential was read, supplied, or committed |
| Display dashboard/wallet/explorer result | PASS | The browser displayed validator, explorer, and test-wallet outcomes without publishing device identifiers |

Proof signature bytes are verified but excluded from V1 ticket and score
derivation, so changing a valid ECDSA proof representation cannot grind a better
ticket. The earlier proof-inclusive run and retained local V1 journal are
obsolete evidence; no local journal is committed.

See [`arduino/HARDWARE_TEST_REPORT.md`](../../arduino/HARDWARE_TEST_REPORT.md)
for the consolidated narrative. Production hardware-backed identity, platform
attestation, direct Wi-Fi E2E, and physical testing outside the classic ESP32
family remain unverified.
