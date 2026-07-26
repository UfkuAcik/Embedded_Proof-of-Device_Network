# EPDN Arduino library

`libraries/EPDN` contains the transport-neutral ticket engine and explicit
identity backends. `WiFiMiner` and `GatewayMiner` use the same canonical EPDN
binary V1 ticket path. The UART gateway carries bytes only; signing remains on
the device.

The current ESP32 development identity is a P-256 private scalar stored in NVS,
with a 33-byte compressed SEC1 public key and RFC6979 deterministic ECDSA
signatures encoded as fixed 64-byte big-endian `r || s`. It is **L0 only**:
ordinary NVS is not proof of hardware-backed identity. Production rejects L0,
and unimplemented L1/L3/L4 backends return failure without fallback.

Ticket eligibility hashes the provisioned public-key hash and canonical
challenge, not ECDSA proof bytes. The proof is still verified, but excluding it
prevents a malicious provisioned key holder from varying ECDSA nonces to grind
lottery scores.

After an epoch is persistently reserved, an exact canonical-challenge hash
match may retrieve the byte-identical submission from a RAM-only retry cache
when the UART gateway explicitly requests a retry. A different challenge for
that epoch fails closed. The cache is intentionally not persisted: a
device/process restart can sacrifice the epoch, but cannot create a second
ticket. Wi-Fi transport keeps its own pending bytes and does not enable the
gateway cache path after a successful POST.

Compile without uploading:

```powershell
arduino-cli compile --fqbn esp32:esp32:esp32 --libraries arduino/libraries arduino/examples/SecurityDiagnostic
arduino-cli compile --fqbn esp32:esp32:esp32 --libraries arduino/libraries arduino/examples/GatewayMiner
arduino-cli compile --fqbn esp32:esp32:esp32 --libraries arduino/libraries arduino/examples/WiFiMiner
```

`secrets_local.h` and `arduino/generated/` are local-only. Never print Wi-Fi
credentials, private keys, certificate enrollment secrets, or MAC addresses.
The serial provisioning frame is bounded and CRC-protected against accidental
corruption, but USB/UART provisioning still requires a physically trusted host.

See `HARDWARE_TEST_REPORT.md` and `board-configs/support-matrix.json` for
measured compile and physical-test evidence. Wi-Fi E2E remains blocked until
the user explicitly supplies a password.
