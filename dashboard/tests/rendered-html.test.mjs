import assert from "node:assert/strict";
import { access, readFile } from "node:fs/promises";
import test from "node:test";

const root = new URL("../", import.meta.url);

async function render(path = "/") {
  const workerUrl = new URL("../dist/server/index.js", import.meta.url);
  workerUrl.searchParams.set("test", `${process.pid}-${Date.now()}`);
  const { default: worker } = await import(workerUrl.href);

  return worker.fetch(
    new Request(`http://localhost${path}`, {
      headers: { accept: "text/html" },
    }),
    {
      ASSETS: {
        fetch: async () => new Response("Not found", { status: 404 }),
      },
    },
    {
      waitUntil() {},
      passThroughOnException() {},
    },
  );
}

test("server-renders the EPDN product instead of starter chrome", async () => {
  const response = await render();
  assert.equal(response.status, 200);
  assert.match(response.headers.get("content-type") ?? "", /^text\/html\b/i);

  const html = await response.text();
  assert.match(html, /<title>EPDN Network<\/title>/i);
  assert.match(html, /PUBLIC CHAIN OBSERVATORY/);
  assert.match(html, /Proof,/);
  assert.match(html, /not power\./);
  assert.match(html, /MY WORKSPACE/);
  assert.match(html, /Sign in for writes/);
  assert.doesNotMatch(html, /codex-preview|react-loading-skeleton|Starter Project/i);
});

test("HTML responses use fresh CSP nonces without unsafe-inline", async () => {
  const firstResponse = await render();
  const firstPolicy =
    firstResponse.headers.get("content-security-policy") ?? "";
  assert.match(firstPolicy, /script-src[^;]*'strict-dynamic'/);
  assert.match(firstPolicy, /script-src-attr 'none'/);
  assert.match(firstPolicy, /style-src-attr 'none'/);
  assert.doesNotMatch(firstPolicy, /'unsafe-inline'/);
  assert.equal(firstResponse.headers.get("cache-control"), "private, no-store");

  const nonceMatch = /'nonce-([^']+)'/.exec(firstPolicy);
  assert.ok(nonceMatch);
  const nonce = nonceMatch[1];
  const html = await firstResponse.text();
  const activeTags = html.match(/<(?:script|style)\b[^>]*>/gi) ?? [];
  assert.ok(activeTags.length > 0);
  for (const tag of activeTags) {
    assert.match(tag, new RegExp(`\\snonce="${nonce}"(?:\\s|>)`));
  }

  const secondResponse = await render();
  const secondPolicy =
    secondResponse.headers.get("content-security-policy") ?? "";
  const secondNonce = /'nonce-([^']+)'/.exec(secondPolicy)?.[1];
  assert.ok(secondNonce);
  assert.notEqual(secondNonce, nonce);
});

test("ships installable metadata and a privacy-safe offline shell", async () => {
  const [manifestText, serviceWorker, offline, layout, viteConfig, app] =
    await Promise.all([
    readFile(new URL("public/manifest.webmanifest", root), "utf8"),
    readFile(new URL("public/sw.js", root), "utf8"),
    readFile(new URL("public/offline.html", root), "utf8"),
    readFile(new URL("app/layout.tsx", root), "utf8"),
    readFile(new URL("vite.config.ts", root), "utf8"),
    readFile(new URL("app/epdn-app.tsx", root), "utf8"),
  ]);
  const manifest = JSON.parse(manifestText);

  assert.equal(manifest.name, "EPDN Network");
  assert.equal(manifest.display, "standalone");
  assert.equal(manifest.start_url, "/");
  assert.ok(manifest.icons.length >= 1);
  assert.match(serviceWorker, /offline\.html/);
  assert.doesNotMatch(serviceWorker, /OFFLINE_ASSETS\s*=\s*\[[^\]]*["']\/["']/);
  assert.match(offline, /private wallet remains encrypted/i);
  assert.doesNotMatch(offline, /\sonclick\s*=/i);
  assert.match(offline, /<a href="\/">Try again<\/a>/);
  assert.match(layout, /manifest:\s*"\/manifest\.webmanifest"/);
  assert.doesNotMatch(viteConfig, /import hostingConfig from/);
  assert.match(viteConfig, /code === "ENOENT"/);
  for (const kind of [
    "miner_registered",
    "miner_paused",
    "miner_resumed",
    "ticket_accepted",
    "transaction_accepted",
    "certificate_revocation_queued",
    "new_block",
    "certificate_revoked",
    "reward",
    "new_epoch",
    "lagged",
  ]) {
    assert.match(app, new RegExp(`"${kind}"`));
  }
  assert.match(app, /parsed\.payload/);
  assert.match(app, /fetchLiveSnapshot/);
  await assert.rejects(access(new URL("app/_sites-preview", root)));
});
