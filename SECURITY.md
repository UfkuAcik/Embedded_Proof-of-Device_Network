# EPDN security policy

EPDN is experimental testnet software. It has not received an independent
security audit and must not protect assets with real monetary value.

## Reporting a vulnerability

Use this repository's GitHub **Report a vulnerability** form so the report
stays private. Do not include private keys, Wi-Fi credentials, device dumps,
eFuse secrets, or personally identifying hardware data in a public issue.
Include:

- the affected version and component;
- a minimal reproduction using disposable test credentials;
- impact and preconditions;
- suggested mitigations, if known.

## Security boundaries

- A provisioned certificate proves possession of the corresponding private key;
  it does not universally prove that code runs on physical hardware.
- L0 identities are development-only and are rejected by production policy.
- L1 software keys can be copied after a sufficiently capable device
  compromise. Clone resistance requires a verified non-exportable L2/L3/L4
  backend and a trusted provisioning process.
- MAC addresses, chip names, serial claims, timing, RSSI, and telemetry are not
  roots of trust.
- A single-validator network and its development randomness are explicitly
  insecure.
- The browser wallet is exposed to browser, XSS, extension, and dependency
  supply-chain risk while unlocked.

## Irreversible operations

The tooling defaults to dry-run for eFuse, permanent Secure Boot/Flash
Encryption, JTAG/UART disable, and anti-rollback changes. Any production plan
must require `--confirm-irreversible-security-changes` and print every proposed
field transition before execution. This repository's automated tests never
perform those operations.
