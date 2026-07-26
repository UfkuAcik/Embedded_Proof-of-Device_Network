# EPDN Dashboard

Responsive PWA for the Embedded Proof-of-Device Network. One product shell
contains three deliberately separated surfaces:

- **Public Explorer** — blocks, epochs, validator agreement, public device IDs,
  firmware/security distributions, and chain status.
- **Authorized Miner Dashboard** — private device labels, health, rewards,
  certificate controls, and SSE events.
- **Local-first Wallet** — P-256 signing, encrypted IndexedDB storage,
  encrypted key-file import/export, QR receive address, lock, and auto-lock.

When no validator is configured or reachable, the UI is visibly marked
`DEMO DATA` and uses a fixed sample dataset. Demo mode never pretends to submit
revocations or broadcast transactions.

## Local run

Node.js 22.13 or newer is required.

```bash
npm install
copy .env.example .env.local
npm run dev
```

Set `EPDN_API_BASE_URL` to the validator origin. It can also be changed for the
current tab with the API control in the header; this value is kept in memory,
not persistent browser storage. The client reads:

- `GET /api/v1/network/status`
- `GET /api/v1/blocks`
- `GET /api/v1/miners`
- `GET /api/v1/events` (SSE)

Signed transfers are posted to `POST /api/v1/transactions` as
`{"transaction_hex":"…"}`. Only canonical public transaction bytes and the
raw 64-byte ES256 signature cross the network.

The wallet accepts whole EPDN testnet units because Protocol V1 defines all
amounts and fees as indivisible `u64` values.

## Authentication and write authorization

The public explorer stays anonymous. The Sites dispatcher may provide SIWC
identity headers for workspace views. Every write path verifies that identity
again on the server; hiding a browser button is not an authorization control.

`POST /api/admin/revoke` rejects anonymous and cross-origin requests, validates
the request shape, then proxies a command to the validator. If the validator
requires a local administrator credential, set `EPDN_ADMIN_API_TOKEN` only in
the server/Sites runtime environment; the proxy sends it through the node's
`x-epdn-admin-token` header. It is never returned to the client, written to
storage, or included in the source.

SIWC proves a ChatGPT identity, not workspace membership. A production
deployment must additionally use Sites access policy or a server-side member
allowlist when the dashboard is workspace-restricted.

## Wallet security boundary

- Web Crypto generates P-256 keys.
- The full private JWK is encrypted with PBKDF2-SHA-256 (310,000 iterations)
  and AES-256-GCM before IndexedDB storage.
- Unlock imports a non-extractable in-memory signing key.
- Lock and five-minute inactivity discard the in-memory reference.
- No mnemonic feature is exposed.
- No private key or password is sent through REST/SSE, logged, put in
  localStorage, cookies, or source.
- Export contains the encrypted record only.

Browser XSS while a wallet is unlocked can still abuse an in-memory key. CSP,
dependency review, short auto-lock, transaction review, and a minimal client
surface reduce this risk but do not eliminate it.

The Worker adds a fresh CSP nonce to each server-rendered script and style tag,
then returns the matching `script-src`/`style-src` policy. Inline script and
style attributes are blocked, as are object/frame embedding and cross-origin
form actions. Nonced HTML responses are private and never cached.

The nonce injector is not an HTML sanitizer: it assumes every rendered
`<script>` and `<style>` tag comes from the trusted Vinext/React renderer. Raw
HTML rendering of user or third-party content must not be introduced without
moving nonce assignment to trusted framework tags (or replacing it with
audited hashes), because a pre-render injection would otherwise receive a
valid nonce.

## Validation

```bash
npm run lint
npm test
```

Tests cover server rendering, removal of starter chrome, PWA/offline metadata,
server-side write authorization, private-key storage/network invariants, and
the Rust/Web Crypto canonical transfer vector.
