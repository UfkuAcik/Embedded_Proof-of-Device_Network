# Protocol fuzzing

These `cargo-fuzz` targets exercise every externally supplied consensus parser:

- `epoch_challenge_decode`
- `device_certificate_decode`
- `ticket_submission_decode`
- `signed_transfer_decode`

Each target accepts arbitrary bytes. Seed corpus entries may use `hex:` text so
the checked-in corpus remains reviewable. When decoding succeeds, the target
requires re-encoding to produce byte-for-byte identical canonical EPDN V1 data.

Run on a supported Linux/macOS fuzzing host with nightly Rust:

```text
cargo install cargo-fuzz
cd protocol
cargo +nightly fuzz run epoch_challenge_decode -- -max_len=1024
cargo +nightly fuzz run device_certificate_decode -- -max_len=4096
cargo +nightly fuzz run ticket_submission_decode -- -max_len=8192
cargo +nightly fuzz run signed_transfer_decode -- -max_len=2048
```

For bounded CI smoke runs, append `-runs=10000`. The corpus contains one valid
cross-platform V1 object and one truncated header per parser. Crashes belong in
the corresponding `artifacts/` directory, which is intentionally not committed.
The normal workspace test `fuzz_corpus` also checks that every seed is valid for
its intended parser (or rejected when truncated) and that valid seeds still
match `test-vectors/v1.json`.

`cargo-fuzz` and libFuzzer sanitizer execution are not supported by this
repository's Windows GNU verification path. Normal workspace builds remain
independent of the fuzz crate.
