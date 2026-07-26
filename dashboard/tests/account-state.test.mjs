import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import ts from "typescript";

const root = new URL("../", import.meta.url);

async function loadAccountModule() {
  const source = await readFile(new URL("app/lib/account.ts", root), "utf8");
  const javascript = ts.transpileModule(source, {
    compilerOptions: {
      module: ts.ModuleKind.ESNext,
      target: ts.ScriptTarget.ES2022,
    },
  }).outputText;
  return import(
    `data:text/javascript;base64,${Buffer.from(javascript).toString("base64")}`
  );
}

test("account responses preserve the validator next_nonce exactly", async () => {
  const account = await loadAccountModule();
  const address = "12".repeat(32);

  assert.deepEqual(
    account.parseWalletAccountState(
      { address, balance: 42, next_nonce: 7 },
      address,
    ),
    { address, balance: 42, nextNonce: 7n },
  );
  assert.throws(
    () =>
      account.parseWalletAccountState(
        { address, balance: 42, next_nonce: Number.MAX_SAFE_INTEGER + 1 },
        address,
      ),
    /invalid account nonce/i,
  );
  assert.throws(
    () =>
      account.parseWalletAccountState(
        { address: "34".repeat(32), balance: 42, next_nonce: 7 },
        address,
      ),
    /another address/i,
  );
});

test("fresh account lookup is no-store and address-scoped", async () => {
  const account = await loadAccountModule();
  const address = "ab".repeat(32);
  let observedUrl = "";
  let observedOptions;
  const fetcher = async (url, options) => {
    observedUrl = String(url);
    observedOptions = options;
    return Response.json({ address, balance: 9, next_nonce: 3 });
  };

  const result = await account.fetchWalletAccountState(
    "https://validator.example/",
    address,
    fetcher,
  );
  assert.equal(
    observedUrl,
    `https://validator.example/api/v1/address/${address}`,
  );
  assert.equal(observedOptions.cache, "no-store");
  assert.equal(result.nextNonce, 3n);
});
