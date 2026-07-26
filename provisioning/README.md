# EPDN provisioning

The Python 3.11 CLI exposes `inspect`, `enroll-dev`, `provision-testnet`,
`provision-production`, `register`, `flash`, `monitor`, `diagnose`,
`renew-certificate`, `revoke`, and `security-plan`.

Install locally with `python -m pip install -e provisioning[crypto]`.
The default `enroll-dev` flow asks the running node CA to issue the certificate,
installs the returned canonical certificate on the device, then registers it
with the reward address. The exact admin routes are `/api/v1/admin/enroll` and
`/api/v1/admin/register`; revocation uses
`/api/v1/admin/miners/{public_id}/revoke`. The client sends the node's required
`x-epdn-admin-token` header. `EPDN_NODE_TOKEN` is mandatory off-loopback; the
documented local token is used only for `localhost`/loopback URLs.

An optional `--local-ca` helper keeps an encrypted private key in ignored
`provisioning/.state/`. Its certificates are intentionally not trusted by the
default node. Supply its password through interactive input or
`EPDN_DEV_CA_PASSWORD`; it is never accepted as an argv value.

`provision-production` has no implementation that writes eFuses. Without
`--confirm-irreversible-security-changes` it refuses. With that exact flag it
prints every planned field and still remains a dry run. The project does not
burn Secure Boot, Flash Encryption, JTAG, UART-download, or anti-rollback fuses.

Serial frames are bounded to 2048 bytes and CRC-protected. CRC detects transport
corruption, not a malicious provisioning host; use a physically trusted USB
connection. Wi-Fi passwords are prompted without echo and wiped from mutable
host buffers where practical.

The default chain is `epdn-local-testnet-v1`. The default firmware allowlist ID
is `SHA256("EPDN_FIRMWARE_ID_V1" || "epdn-miner-development")`; both can be
overridden explicitly for a different test network.

The final local hardware run exercised node-CA enrollment, certificate install,
registration, and revocation for a development-only physical identity. Public
identity values and device security posture are omitted; no irreversible
security setting or production credential was used.
