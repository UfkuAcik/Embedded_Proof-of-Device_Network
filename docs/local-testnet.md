# Local testnet operations

The cross-platform runner uses loopback only, three distinct validator keys,
separate journals, bounded health checks, and a documented test-only admin
token that is never written to its process manifest.

## One-shot smoke

```bash
python scripts/testnet.py smoke
```

The command runs a locked incremental `epdn-node` build so an old artifact
cannot silently be reused, starts temporary nodes on ports 8745–8747, verifies
their public status, runs the deterministic
three-validator commit/reveal test, terminates every child, and deletes the
temporary state.

For CI or when the default ports are occupied:

```bash
python scripts/testnet.py --ports 18745,18746,18747 smoke
```

## Persistent development processes

```bash
python scripts/testnet.py up
python scripts/testnet.py status
python scripts/testnet.py down
```

State and JSON logs live below `.epdn/testnet/` and are ignored by Git. `down`
checks that each recorded PID still resolves to the recorded `epdn-node`
binary before signaling it. A mismatch is refused; executable-path verification
narrows, but cannot eliminate, PID-reuse risk involving the same binary.

These are three operational API fixtures, not connected peers. See
[`consensus.md`](consensus.md) for the exact limitation.

## Container

`Dockerfile` builds only the Rust node and sends only the Rust manifests/source
through the allowlisted Docker context. A container binds to `0.0.0.0:8745`,
so the node intentionally refuses to start unless the operator supplies:

```text
EPDN_ADMIN_TOKEN
EPDN_CORS_ORIGINS
EPDN_DEV_CA_PRIVATE_KEY_HEX
EPDN_VALIDATOR_PRIVATE_KEY_HEX
```

The two signing keys must be distinct, valid 32-byte P-256 scalars encoded as
64 hexadecimal characters. Persist `/var/lib/epdn`. Do not pass keys in image
layers or command arguments; use the deployment platform's runtime secret
facility.

Docker was not installed on the development workstation during this MVP, so no
local image-build result is claimed. GitHub CI contains the reproducible build
gate.
