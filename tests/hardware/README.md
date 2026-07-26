# Hardware evidence

Committed reports contain only sanitized, non-secret evidence. Local raw serial
captures belong under `tests/hardware/results/local/`, which is Git-ignored
because device identifiers or credentials may appear unexpectedly.

Public reports omit capture dates and timezones, workstation and driver
versions, port names, USB identifiers, exact chip revisions, memory readings,
raw security posture, public identity values, and certificate bytes.

Run records use:

- `PASS` — command and expected behavior were observed;
- `FAIL` — command ran and contradicted the expectation;
- `BLOCKED` — a required physical condition or permission was unavailable;
- `NOT RUN` — no attempt was made.

Compile-only results never count as physical hardware evidence.
