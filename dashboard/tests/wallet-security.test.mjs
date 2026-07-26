import assert from "node:assert/strict";
import {
  createECDH,
  createHash,
  createPublicKey,
  verify,
  webcrypto,
} from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { indexedDB } from "fake-indexeddb";
import ts from "typescript";

const root = new URL("../", import.meta.url);

test("wallet keeps private material inside Web Crypto and encrypted IndexedDB", async () => {
  const wallet = await readFile(new URL("app/lib/wallet.ts", root), "utf8");

  assert.match(wallet, /indexedDB\.open/);
  assert.match(wallet, /PBKDF2_ITERATIONS\s*=\s*310_000/);
  assert.match(wallet, /name:\s*"PBKDF2"/);
  assert.match(wallet, /name:\s*"AES-GCM"/);
  assert.match(wallet, /namedCurve:\s*"P-256"/);
  assert.match(wallet, /extractable false|false,\s*\["sign"\]/s);
  assert.match(wallet, /plaintext\.fill\(0\)/);
  assert.match(wallet, /additionalData:\s*walletMetadataBinding\(record\)/);
  assert.match(wallet, /identity\.address !== record\.address/);
  assert.doesNotMatch(wallet, /localStorage|sessionStorage|document\.cookie|console\./);
  assert.doesNotMatch(wallet, /\bfetch\s*\(/);
});

test("wallet encoding matches the Rust transfer boundary", async () => {
  const wallet = await readFile(new URL("app/lib/wallet.ts", root), "utf8");
  const app = await readFile(new URL("app/epdn-app.tsx", root), "utf8");

  assert.match(wallet, /EPDN_WALLET_ADDRESS_V1/);
  assert.match(wallet, /compressP256PublicKey/);
  assert.match(wallet, /encoder\.encode\("EPDN"\)/);
  assert.match(wallet, /Uint8Array\.of\(6\)/);
  assert.match(wallet, /u16\(1\)/);
  assert.match(wallet, /Uint8Array\.of\(1\)/);
  assert.match(wallet, /EPDN_TRANSFER_SIGNATURE_V1/);
  assert.match(wallet, /signature\.length !== 64/);
  assert.match(wallet, /transaction_hex/);
  assert.match(app, /JSON\.stringify\(envelope\)/);
  assert.match(app, /fetchWalletAccountState\(apiBase, wallet\.address\)/);
  assert.match(app, /function parseProtocolUnits/);
  assert.match(app, /step="1"/);
  assert.doesNotMatch(app, /parseMicroUnits|1_000_000n/);
  assert.doesNotMatch(app, /nonce:\s*BigInt\(Date\.now\(\)\)/);
  assert.doesNotMatch(app, /JSON\.stringify\(wallet\)|body:\s*JSON\.stringify\([^)]*privateKey/);
});

test("write actions authenticate server-side and keep admin token server-only", async () => {
  const [route, app, packageJson] = await Promise.all([
    readFile(new URL("app/api/admin/revoke/route.ts", root), "utf8"),
    readFile(new URL("app/epdn-app.tsx", root), "utf8"),
    readFile(new URL("package.json", root), "utf8"),
  ]);

  assert.match(route, /await getChatGPTUser\(\)/);
  assert.match(route, /status:\s*401/);
  assert.match(route, /EPDN_ADMIN_API_TOKEN/);
  assert.match(route, /headers\.set\("x-epdn-admin-token", adminToken\)/);
  assert.doesNotMatch(route, /x-epdn-actor|user\.email/);
  assert.doesNotMatch(route, /headers\.set\("authorization"/i);
  assert.match(route, /Cross-origin write rejected/);
  assert.match(route, /baseUrl\.pathname !== "\/"/);
  assert.match(route, /baseUrl\.username|baseUrl\.password/);
  assert.match(route, /new URL\(\s*`\/api\/v1\/miners\//);
  assert.doesNotMatch(app, /EPDN_ADMIN_API_TOKEN/);
  assert.doesNotMatch(packageJson, /react-loading-skeleton/);
});

test("Web Crypto transfer bytes match the shared Rust vector", async () => {
  Object.defineProperty(globalThis, "crypto", {
    configurable: true,
    value: webcrypto,
  });
  const [source, vectorText] = await Promise.all([
    readFile(new URL("app/lib/wallet.ts", root), "utf8"),
    readFile(
      new URL("../../protocol/test-vectors/v1.json", import.meta.url),
      "utf8",
    ),
  ]);
  const javascript = ts.transpileModule(source, {
    compilerOptions: {
      module: ts.ModuleKind.ESNext,
      target: ts.ScriptTarget.ES2022,
    },
  }).outputText;
  const walletModule = await import(
    `data:text/javascript;base64,${Buffer.from(javascript).toString("base64")}`
  );
  const vector = JSON.parse(vectorText);
  const privateBytes = Buffer.from(vector.wallet_private_key_hex, "hex");
  const ecdh = createECDH("prime256v1");
  ecdh.setPrivateKey(privateBytes);
  const uncompressed = ecdh.getPublicKey(undefined, "uncompressed");
  const compressed = ecdh.getPublicKey(undefined, "compressed");
  const base64Url = (value) => Buffer.from(value).toString("base64url");
  const privateJwk = {
    kty: "EC",
    crv: "P-256",
    x: base64Url(uncompressed.subarray(1, 33)),
    y: base64Url(uncompressed.subarray(33, 65)),
    d: base64Url(privateBytes),
    ext: true,
    key_ops: ["sign"],
  };
  const privateKey = await webcrypto.subtle.importKey(
    "jwk",
    privateJwk,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"],
  );
  const address = createHash("sha256")
    .update("EPDN_WALLET_ADDRESS_V1")
    .update(compressed)
    .digest("hex");
  const wallet = {
    address,
    publicKey: base64Url(compressed),
    privateKey,
    createdAt: "test-vector",
  };
  const draft = {
    chainId: "epdn-vector-testnet",
    recipient: "55".repeat(32),
    amount: 25n,
    fee: 2n,
    nonce: 7n,
  };

  const unsigned = walletModule.canonicalTransferBytes(wallet, draft);
  assert.equal(Buffer.from(unsigned).toString("hex"), vector.transfer_unsigned_hex);

  const envelope = await walletModule.signTransfer(wallet, draft);
  const transaction = Buffer.from(envelope.transaction_hex, "hex");
  assert.deepEqual(
    transaction.subarray(0, unsigned.length),
    Buffer.from(unsigned),
  );
  assert.equal(transaction.readUInt16BE(unsigned.length), 64);
  const signature = transaction.subarray(unsigned.length + 2);
  assert.equal(signature.length, 64);
  const publicKey = createPublicKey({
    key: {
      kty: "EC",
      crv: "P-256",
      x: privateJwk.x,
      y: privateJwk.y,
    },
    format: "jwk",
  });
  assert.equal(
    verify(
      "sha256",
      Buffer.concat([
        Buffer.from("EPDN_TRANSFER_SIGNATURE_V1"),
        Buffer.from(unsigned),
      ]),
      { key: publicKey, dsaEncoding: "ieee-p1363" },
      signature,
    ),
    true,
  );
});

test("wallet create and unlock keep only ciphertext in IndexedDB", async () => {
  Object.defineProperties(globalThis, {
    crypto: { configurable: true, value: webcrypto },
    indexedDB: { configurable: true, value: indexedDB },
  });
  const source = await readFile(new URL("app/lib/wallet.ts", root), "utf8");
  const javascript = ts.transpileModule(source, {
    compilerOptions: {
      module: ts.ModuleKind.ESNext,
      target: ts.ScriptTarget.ES2022,
    },
  }).outputText;
  const walletModule = await import(
    `data:text/javascript;base64,${Buffer.from(javascript).toString("base64")}#storage`
  );
  const password = "test-only-correct-horse-device-proof";
  const created = await walletModule.createEncryptedWallet(password);
  const stored = await walletModule.loadEncryptedWallet();

  assert.equal(stored.format, "epdn-encrypted-key-v2");
  assert.equal(stored.address, created.address);
  assert.equal(stored.publicKeyJwk.d, undefined);
  assert.equal("privateKey" in stored, false);
  assert.doesNotMatch(JSON.stringify(stored), new RegExp(password));
  assert.ok(stored.ciphertext.length > 100);

  await assert.rejects(
    walletModule.createEncryptedWallet("different-test-only-wallet-password"),
    /already exists/i,
  );
  assert.deepEqual(await walletModule.loadEncryptedWallet(), stored);

  const originalRecord = JSON.stringify(stored);
  const mutations = [
    (record) => {
      record.address =
        `${record.address[0] === "a" ? "b" : "a"}${record.address.slice(1)}`;
    },
    (record) => {
      const index = 8;
      record.publicKey =
        `${record.publicKey.slice(0, index)}${
          record.publicKey[index] === "A" ? "B" : "A"
        }${record.publicKey.slice(index + 1)}`;
    },
    (record) => {
      record.createdAt = `${record.createdAt}-tampered`;
    },
  ];
  for (const mutate of mutations) {
    const tampered = structuredClone(stored);
    mutate(tampered);
    await assert.rejects(
      walletModule.importEncryptedWallet(JSON.stringify(tampered), password),
      /password or key file is invalid/i,
    );
    assert.deepEqual(await walletModule.loadEncryptedWallet(), stored);
  }

  await assert.rejects(
    walletModule.importEncryptedWallet(originalRecord, "wrong password"),
    /password or key file is invalid/i,
  );
  assert.deepEqual(await walletModule.loadEncryptedWallet(), stored);

  await walletModule.importEncryptedWallet(originalRecord, password);
  const unlocked = await walletModule.unlockEncryptedWallet(password);
  assert.equal(unlocked.address, created.address);
  assert.equal(unlocked.privateKey.extractable, false);
  assert.deepEqual(unlocked.privateKey.usages, ["sign"]);

  let activeSession = unlocked;
  activeSession = null;
  assert.equal(activeSession, null);
});

test("legacy wallet identity is verified before one-way v2 migration", async () => {
  Object.defineProperties(globalThis, {
    crypto: { configurable: true, value: webcrypto },
    indexedDB: { configurable: true, value: indexedDB },
  });
  const source = await readFile(new URL("app/lib/wallet.ts", root), "utf8");
  const javascript = ts.transpileModule(source, {
    compilerOptions: {
      module: ts.ModuleKind.ESNext,
      target: ts.ScriptTarget.ES2022,
    },
  }).outputText;
  const walletModule = await import(
    `data:text/javascript;base64,${Buffer.from(javascript).toString("base64")}#legacy`
  );
  const password = "legacy-test-only-correct-horse-device";
  const generated = await webcrypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );
  const privateJwk = await webcrypto.subtle.exportKey(
    "jwk",
    generated.privateKey,
  );
  const x = Buffer.from(privateJwk.x, "base64url");
  const y = Buffer.from(privateJwk.y, "base64url");
  const compressed = Buffer.concat([
    Buffer.from([(y[31] & 1) === 0 ? 0x02 : 0x03]),
    x,
  ]);
  const address = createHash("sha256")
    .update("EPDN_WALLET_ADDRESS_V1")
    .update(compressed)
    .digest("hex");
  const salt = webcrypto.getRandomValues(new Uint8Array(16));
  const iv = webcrypto.getRandomValues(new Uint8Array(12));
  const passwordMaterial = await webcrypto.subtle.importKey(
    "raw",
    Buffer.from(password),
    "PBKDF2",
    false,
    ["deriveKey"],
  );
  const aesKey = await webcrypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt,
      iterations: 310_000,
    },
    passwordMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"],
  );
  const ciphertext = await webcrypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    aesKey,
    Buffer.from(JSON.stringify(privateJwk)),
  );
  const legacyRecord = {
    format: "epdn-encrypted-key-v1",
    address,
    publicKey: compressed.toString("base64url"),
    publicKeyJwk: {
      kty: "EC",
      crv: "P-256",
      x: privateJwk.x,
      y: privateJwk.y,
      ext: true,
      key_ops: ["verify"],
    },
    ciphertext: Buffer.from(ciphertext).toString("base64url"),
    iv: Buffer.from(iv).toString("base64url"),
    salt: Buffer.from(salt).toString("base64url"),
    kdf: {
      name: "PBKDF2",
      hash: "SHA-256",
      iterations: 310_000,
    },
    cipher: "AES-GCM-256",
    createdAt: "2026-07-26T00:00:00.000Z",
  };

  await assert.rejects(
    walletModule.importEncryptedWallet(
      JSON.stringify({ ...legacyRecord, address: "ab".repeat(32) }),
      password,
    ),
    /password or key file is invalid/i,
  );

  const unlocked = await walletModule.importEncryptedWallet(
    JSON.stringify(legacyRecord),
    password,
  );
  assert.equal(unlocked.address, address);
  assert.equal(
    (await walletModule.loadEncryptedWallet()).format,
    "epdn-encrypted-key-v2",
  );
});
