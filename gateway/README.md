# EPDN Gateway

The gateway is a cross-platform Python UART relay. It fetches a bounded
canonical EPDN binary V1 challenge, transfers it to `GatewayMiner`, receives the
device-created signed ticket submission, validates envelope shape and bounds,
and forwards the exact bytes to the node.

There is intentionally no signing API, device private key, deterministic proof,
or ticket constructor in this package. A compromised gateway can drop, delay,
or replay traffic, but it cannot create a valid device signature. The device's
persistent epoch guard rejects old/duplicate challenges and the node performs
certificate, signature, epoch, firmware, revocation, and duplicate validation.
Transient node failures retry the same device-signed bytes from gateway RAM;
the device is not asked to sign the reserved epoch again. A simultaneous device
and gateway process restart can sacrifice that epoch for duplicate safety.
The node challenge endpoint is device-specific and uses the registered public
ID plus firmware ID. The default firmware ID matches
`SHA256("EPDN_FIRMWARE_ID_V1" || "epdn-miner-development")`.

UART uses `EPG1 | type:u8 | length:u16be | payload | crc32be`. CRC catches
accidental corruption; it is not authentication. HTTPS is required by default.
Plain HTTP requires `--allow-insecure-development-http` and is intended only
for a local test node.

```powershell
python -m pip install -e gateway
epdn-gateway --node-url http://127.0.0.1:8745 --port PORT_NAME --device-public-id DEVICE_ID --allow-insecure-development-http
```

The final proof-exclusion firmware was physically verified on classic
ESP32-family hardware through this UART contract: ticket acceptance, byte-identical
same-boot retry, duplicate rejection, block/reward, and post-revocation
rejection all passed. A real non-empty EPSJ V2 journal also passed stop/restart
with height, epoch, wallet balance, and revoked state preserved. The ignored V1
journal remains only as obsolete evidence and is not treated as V2-compatible.
