# Sanitized development environment report

This public report intentionally omits its capture date and timezone, operating
system build, local tool versions, usernames and home paths, hostnames, serial
port names, USB bridge identifiers and serials, driver metadata, network
identifiers, and unique device identifiers. Reproducible tool versions belong
in CI configuration rather than in a workstation fingerprint.

No Wi-Fi SSID or password was read into a committed artifact. Local credentials
and raw hardware captures remain in Git-ignored paths.

## Physical target

| Item | Public evidence |
|---|---|
| Target family | Classic ESP32 family |
| Transport | Local USB/UART |
| Exact board and revision | Intentionally omitted |
| Unique identifiers | Intentionally omitted |
| Test scope | Read-only diagnostics, protocol vectors, and UART gateway flow |

The inspection did not perform an irreversible security operation. Per-device
security posture and raw diagnostic values are intentionally excluded from the
public report; this evidence must not be interpreted as a production security
certification.
