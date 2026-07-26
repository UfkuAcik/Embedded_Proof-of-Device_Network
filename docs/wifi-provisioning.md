# Wi-Fi provisioning

The MVP implements serial provisioning so credentials do not need to be embedded
in source code.

## Rules

- SSID may be detected from the active operating-system connection.
- Reading a saved Wi-Fi password requires separate explicit user approval.
- Password input must be masked and must not be placed on a command line.
- Logs contain only `credential_present=true/false`, never credential contents.
- Local secret files and generated headers are Git-ignored.
- The provisioner handles only the selected network; it does not enumerate or
  export unrelated saved credentials.
- Secrets are never sent to a remote service or telemetry endpoint.

## Serial flow

1. Host opens the explicitly selected serial port.
2. Miner and host exchange a bounded, versioned provisioning hello.
3. Host prompts locally for SSID/password without echo.
4. Credentials are sent only over the local serial link and stored in the
   platform's designated persistent storage.
5. Firmware returns a status code, not the credentials.
6. Buffers are cleared where the platform permits.

Serial provisioning protects repository and log hygiene, but the unencrypted
local serial cable is not confidential against a compromised host or physical
observer. Production provisioning should use an authenticated encrypted channel.
