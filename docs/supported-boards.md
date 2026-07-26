# Supported-board matrix

Labels:

- **physical-tested** — compile, upload, and behavior verified on named
  hardware, with evidence.
- **chip-tested/model-unknown** — chip target verified but commercial board
  model not proven.
- **compile-only** — a pinned board core compiled in CI; no physical claim.
- **planned** — abstraction and test procedure exist; build is not yet a gate.

| Family | Direct network | Identity path | MVP status |
|---|---|---|---|
| Classic ESP32 | Wi-Fi / UART gateway | development-only; stronger classes require model-specific evidence | family-level physical test; exact target details omitted |
| ESP32-S2/S3/C2/C3/C5/C6/C61/H2/P4 | model-dependent Wi-Fi, Thread, Ethernet, or gateway | explicit ESP-IDF capability adapter | compile-only or planned; never inferred from name |
| ESP8266 | Wi-Fi / UART gateway | L0/L1; L3 with secure element | planned |
| Raspberry Pi Pico W / RP2040 | Wi-Fi or gateway | L0/L1; L3 with secure element | compile-only |
| Nano 33 IoT / MKR WiFi 1010 | Wi-Fi | onboard/external ATECC where verified | planned |
| UNO WiFi Rev2 | Wi-Fi | platform adapter or L3 | planned |
| SAMD | module/gateway-dependent | L1 or L3 | planned |
| STM32 Arduino cores | board-dependent | L1/L2/L3 by exact MCU/circuit | planned |
| Renesas Arduino cores | board-dependent | L1/L2/L3 by exact target | planned |

ESP32 variants without native Wi-Fi, or with host-dependent radio support, must
use a declared gateway transport rather than assume connectivity.

## Hardware qualification procedure

1. Record exact FQBN, board marking, USB bridge, chip target and revision.
2. Compile with strict warnings using a pinned core.
3. Run the diagnostic sketch and capture sanitized serial output.
4. Verify crypto/key capability; do not infer it from a family macro.
5. Test power loss, reconnect, persistent-state corruption, and bounded inputs.
6. Record the evidence path and date before changing the matrix label.
