# Continuous-integration gates

`.github/workflows/ci.yml` runs independent, least-privilege jobs:

- Rust formatting, Clippy with warnings denied, workspace tests, and a RustSec
  dependency audit;
- hash-locked Python provisioning, gateway, and indexer tests plus a
  vulnerability audit;
- dashboard locked install, lint, build, wallet/PWA security tests, and a
  production-dependency audit;
- current-tree and full-Git-history secret/path scans;
- pinned Arduino CLI 1.5.0 and ESP32 core 2.0.11 compile matrix for classic
  ESP32, S2, S3, and C3, plus the expected L0-production failure;
- three-process node API smoke plus deterministic validator agreement test;
- Docker node image build on the GitHub-hosted Linux runner.

Third-party Actions are pinned to immutable commit SHAs, Python CI dependencies
are installed from `requirements/ci.lock` with package hashes, Cargo and npm use
their checked-in lockfiles, and Docker base-image tags are paired with immutable
manifest digests.

CI uses public development fixtures only. It must never receive a Wi-Fi
password, production certificate authority key, device identity, wallet key,
or production administrator token.

Arduino CI is compile-only. It is not evidence of execution on ESP32 hardware.
Likewise, the Docker job is the image-build evidence; a local Docker result is
not claimed. The status of the workflow attached to the current Git commit is
the authoritative hosted-run result.

The custom secret scanner is a focused guard, not a replacement for repository
host secret protection or an external leak-response process. Rotate and revoke
any credential that reaches version control even if later removed.
