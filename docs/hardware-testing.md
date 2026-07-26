# Hardware test procedure

## Public target description

The physical flow was exercised on classic ESP32-family development hardware
over a local USB/UART connection. Public reports omit the port, bridge, USB
identifiers, exact chip and revision, flash geometry, driver details, raw
security posture, MAC address, and all unique serial data.

## Safe sequence

1. Keep tool versions and raw board-list output only in a local ignored record.
2. Confirm the selected port is still the same USB device.
3. Compile `SecurityDiagnostic` for the explicit classic ESP32 FQBN.
4. Print the exact application/partition writes before upload.
5. Upload without chip erase or eFuse/security commands.
6. Capture bounded serial output locally; publish only capability-level results.
7. Compile and upload the miner using development identity policy.
8. Provision Wi-Fi only through masked local input, or use the UART gateway.
9. Correlate challenge, ticket, duplicate rejection, revocation, block, and
   reward using public hashes—not secrets.

Firmware upload replaces the current application image. It is requested for the
MVP but is not equivalent to an irreversible fuse operation.

## Evidence labels

Every result is `PASS`, `FAIL`, `BLOCKED`, or `NOT RUN`. Compile success is not
physical proof. A missing password, disconnected board, or denied port must be
reported as a blocker with the exact remaining command.
