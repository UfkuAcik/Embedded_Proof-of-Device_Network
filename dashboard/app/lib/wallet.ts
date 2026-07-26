const DB_NAME = "epdn-wallet-v1";
const STORE_NAME = "encrypted-wallets";
const RECORD_KEY = "primary";
const PBKDF2_ITERATIONS = 310_000;
const CURRENT_WALLET_FORMAT = "epdn-encrypted-key-v2";
const LEGACY_WALLET_FORMAT = "epdn-encrypted-key-v1";
const WALLET_METADATA_DOMAIN = "EPDN_WALLET_METADATA_V2";
const WALLET_KEY_CHECK_DOMAIN = "EPDN_WALLET_KEY_CHECK_V2";
const encoder = new TextEncoder();
const decoder = new TextDecoder();

export type EncryptedWalletRecord = {
  format: typeof CURRENT_WALLET_FORMAT | typeof LEGACY_WALLET_FORMAT;
  address: string;
  publicKey: string;
  publicKeyJwk: JsonWebKey;
  ciphertext: string;
  iv: string;
  salt: string;
  kdf: {
    name: "PBKDF2";
    hash: "SHA-256";
    iterations: number;
  };
  cipher: "AES-GCM-256";
  createdAt: string;
};

export type UnlockedWallet = {
  address: string;
  publicKey: string;
  privateKey: CryptoKey;
  createdAt: string;
};

export type TransferDraft = {
  chainId: string;
  recipient: string;
  amount: bigint;
  fee: bigint;
  nonce: bigint;
};

export type SignedTransfer = {
  transaction_hex: string;
};

function bytesToBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (let index = 0; index < bytes.length; index += 1) {
    binary += String.fromCharCode(bytes[index]);
  }
  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll("=", "");
}

function base64UrlToBytes(value: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new Error("Invalid base64url wallet field.");
  }
  const normalized = value.replaceAll("-", "+").replaceAll("_", "/");
  const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
  const binary = atob(padded);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function bytesToHex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function hexToBytes(value: string): Uint8Array {
  if (!/^[0-9a-f]{64}$/.test(value)) {
    throw new Error("EPDN addresses must be 32-byte lowercase hexadecimal.");
  }
  const output = new Uint8Array(32);
  for (let index = 0; index < output.length; index += 1) {
    output[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  }
  return output;
}

function compressP256PublicKey(uncompressed: Uint8Array): Uint8Array {
  if (uncompressed.length !== 65 || uncompressed[0] !== 0x04) {
    throw new Error("Web Crypto returned an invalid P-256 public key.");
  }
  const compressed = new Uint8Array(33);
  compressed[0] = (uncompressed[64] & 1) === 0 ? 0x02 : 0x03;
  compressed.set(uncompressed.slice(1, 33), 1);
  return compressed;
}

function compressedPublicKeyFromJwk(jwk: JsonWebKey): Uint8Array {
  if (
    jwk.kty !== "EC" ||
    jwk.crv !== "P-256" ||
    typeof jwk.x !== "string" ||
    typeof jwk.y !== "string"
  ) {
    throw new Error("Wallet key is not a P-256 JWK.");
  }
  const x = base64UrlToBytes(jwk.x);
  const y = base64UrlToBytes(jwk.y);
  if (x.length !== 32 || y.length !== 32) {
    throw new Error("Wallet key has invalid P-256 coordinates.");
  }
  const compressed = new Uint8Array(33);
  compressed[0] = (y[31] & 1) === 0 ? 0x02 : 0x03;
  compressed.set(x, 1);
  return compressed;
}

async function addressForPublicKey(publicKey: Uint8Array): Promise<string> {
  const digest = new Uint8Array(
    await crypto.subtle.digest(
      "SHA-256",
      concat(encoder.encode("EPDN_WALLET_ADDRESS_V1"), publicKey),
    ),
  );
  return bytesToHex(digest);
}

function walletMetadataBinding(record: EncryptedWalletRecord): Uint8Array {
  return encoder.encode(
    [
      WALLET_METADATA_DOMAIN,
      record.address,
      record.publicKey,
      record.publicKeyJwk.kty,
      record.publicKeyJwk.crv,
      record.publicKeyJwk.x,
      record.publicKeyJwk.y,
      record.createdAt,
    ].join("\u0000"),
  );
}

async function deriveAesKey(
  password: string,
  salt: Uint8Array,
): Promise<CryptoKey> {
  const material = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveKey"],
  );

  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt,
      iterations: PBKDF2_ITERATIONS,
    },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

type VerifiedWalletIdentity = {
  address: string;
  publicKey: string;
  publicKeyJwk: JsonWebKey;
  privateKey: CryptoKey;
};

async function verifyPrivateJwk(
  privateJwk: JsonWebKey,
): Promise<VerifiedWalletIdentity> {
  if (
    privateJwk.kty !== "EC" ||
    privateJwk.crv !== "P-256" ||
    typeof privateJwk.x !== "string" ||
    typeof privateJwk.y !== "string" ||
    typeof privateJwk.d !== "string" ||
    base64UrlToBytes(privateJwk.d).length !== 32
  ) {
    throw new Error("Wallet private key is not a valid P-256 JWK.");
  }
  const publicKeyBytes = compressedPublicKeyFromJwk(privateJwk);
  const publicKey = bytesToBase64Url(publicKeyBytes);
  const address = await addressForPublicKey(publicKeyBytes);
  const publicKeyJwk: JsonWebKey = {
    kty: "EC",
    crv: "P-256",
    x: privateJwk.x,
    y: privateJwk.y,
    ext: true,
    key_ops: ["verify"],
  };
  const [privateKey, verificationKey] = await Promise.all([
    crypto.subtle.importKey(
      "jwk",
      privateJwk,
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["sign"],
    ),
    crypto.subtle.importKey(
      "jwk",
      publicKeyJwk,
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    ),
  ]);
  const checkMessage = encoder.encode(WALLET_KEY_CHECK_DOMAIN);
  const checkSignature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    privateKey,
    checkMessage,
  );
  if (
    !(await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      verificationKey,
      checkSignature,
      checkMessage,
    ))
  ) {
    throw new Error("Wallet private and public keys do not match.");
  }
  return { address, publicKey, publicKeyJwk, privateKey };
}

async function encryptWalletRecord(
  password: string,
  privateJwk: JsonWebKey,
  identity: VerifiedWalletIdentity,
  createdAt: string,
): Promise<EncryptedWalletRecord> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const record: EncryptedWalletRecord = {
    format: CURRENT_WALLET_FORMAT,
    address: identity.address,
    publicKey: identity.publicKey,
    publicKeyJwk: identity.publicKeyJwk,
    ciphertext: "",
    iv: bytesToBase64Url(iv),
    salt: bytesToBase64Url(salt),
    kdf: {
      name: "PBKDF2",
      hash: "SHA-256",
      iterations: PBKDF2_ITERATIONS,
    },
    cipher: "AES-GCM-256",
    createdAt,
  };
  const aesKey = await deriveAesKey(password, salt);
  const plaintext = encoder.encode(JSON.stringify(privateJwk));
  try {
    const encrypted = await crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv,
        additionalData: walletMetadataBinding(record),
      },
      aesKey,
      plaintext,
    );
    record.ciphertext = bytesToBase64Url(new Uint8Array(encrypted));
    return record;
  } finally {
    plaintext.fill(0);
  }
}

async function decryptAndVerifyWallet(
  record: EncryptedWalletRecord,
  password: string,
): Promise<{ identity: VerifiedWalletIdentity; privateJwk: JsonWebKey }> {
  const aesKey = await deriveAesKey(password, base64UrlToBytes(record.salt));
  const algorithm: AesGcmParams = {
    name: "AES-GCM",
    iv: base64UrlToBytes(record.iv),
  };
  if (record.format === CURRENT_WALLET_FORMAT) {
    algorithm.additionalData = walletMetadataBinding(record);
  }
  const decrypted = await crypto.subtle.decrypt(
    algorithm,
    aesKey,
    base64UrlToBytes(record.ciphertext),
  );
  let privateJwk: JsonWebKey;
  const plaintext = new Uint8Array(decrypted);
  try {
    privateJwk = JSON.parse(decoder.decode(plaintext)) as JsonWebKey;
  } finally {
    plaintext.fill(0);
  }
  const identity = await verifyPrivateJwk(privateJwk);
  if (
    identity.address !== record.address ||
    identity.publicKey !== record.publicKey ||
    identity.publicKeyJwk.x !== record.publicKeyJwk.x ||
    identity.publicKeyJwk.y !== record.publicKeyJwk.y
  ) {
    throw new Error("Wallet metadata does not match its encrypted private key.");
  }
  return { identity, privateJwk };
}

function openDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, 1);
    request.onupgradeneeded = () => {
      if (!request.result.objectStoreNames.contains(STORE_NAME)) {
        request.result.createObjectStore(STORE_NAME);
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () =>
      reject(new Error("Unable to open encrypted wallet storage."));
  });
}

async function withStore<T>(
  mode: IDBTransactionMode,
  operation: (store: IDBObjectStore) => IDBRequest<T>,
): Promise<T> {
  const database = await openDatabase();
  try {
    return await new Promise<T>((resolve, reject) => {
      const transaction = database.transaction(STORE_NAME, mode);
      const request = operation(transaction.objectStore(STORE_NAME));
      let result: T;
      let settled = false;
      const fail = (message: string) => {
        if (!settled) {
          settled = true;
          reject(new Error(message));
        }
      };
      request.onsuccess = () => {
        result = request.result;
      };
      request.onerror = () => fail("Encrypted wallet storage failed.");
      transaction.onerror = () => fail("Encrypted wallet storage failed.");
      transaction.onabort = () =>
        fail("Encrypted wallet storage was interrupted.");
      transaction.oncomplete = () => {
        if (!settled) {
          settled = true;
          resolve(result);
        }
      };
    });
  } finally {
    database.close();
  }
}

async function putRecord(record: EncryptedWalletRecord): Promise<void> {
  await withStore("readwrite", (store) => store.put(record, RECORD_KEY));
}

async function insertRecord(record: EncryptedWalletRecord): Promise<void> {
  try {
    await withStore("readwrite", (store) => store.add(record, RECORD_KEY));
  } catch {
    throw new Error(
      "An encrypted wallet already exists or wallet storage is unavailable.",
    );
  }
}

export async function loadEncryptedWallet(): Promise<EncryptedWalletRecord | null> {
  const record = await withStore<EncryptedWalletRecord | undefined>(
    "readonly",
    (store) => store.get(RECORD_KEY),
  );
  if (!record) return null;
  assertEncryptedWalletRecord(record);
  return record;
}

export async function createEncryptedWallet(
  password: string,
): Promise<UnlockedWallet> {
  if (password.length < 12) {
    throw new Error("Use at least 12 characters for the wallet password.");
  }

  const generated = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );
  const [privateJwk, rawPublicKey] = await Promise.all([
    crypto.subtle.exportKey("jwk", generated.privateKey),
    crypto.subtle.exportKey("raw", generated.publicKey),
  ]);
  const publicKeyBytes = compressP256PublicKey(new Uint8Array(rawPublicKey));
  const identity = await verifyPrivateJwk(privateJwk);
  if (identity.publicKey !== bytesToBase64Url(publicKeyBytes)) {
    throw new Error("Web Crypto returned inconsistent P-256 key material.");
  }
  const record = await encryptWalletRecord(
    password,
    privateJwk,
    identity,
    new Date().toISOString(),
  );
  await insertRecord(record);

  return {
    address: identity.address,
    publicKey: record.publicKey,
    privateKey: identity.privateKey,
    createdAt: record.createdAt,
  };
}

export async function unlockEncryptedWallet(
  password: string,
): Promise<UnlockedWallet> {
  const record = await loadEncryptedWallet();
  if (!record) throw new Error("No local wallet was found.");
  assertEncryptedWalletRecord(record);

  let verified: Awaited<ReturnType<typeof decryptAndVerifyWallet>>;
  try {
    verified = await decryptAndVerifyWallet(record, password);
  } catch {
    throw new Error("The wallet password or key file is invalid.");
  }
  if (record.format === LEGACY_WALLET_FORMAT) {
    const migrated = await encryptWalletRecord(
      password,
      verified.privateJwk,
      verified.identity,
      record.createdAt,
    );
    await putRecord(migrated);
  }
  return {
    address: verified.identity.address,
    publicKey: verified.identity.publicKey,
    privateKey: verified.identity.privateKey,
    createdAt: record.createdAt,
  };
}

export async function exportEncryptedWallet(): Promise<string> {
  const record = await loadEncryptedWallet();
  if (!record) throw new Error("No encrypted wallet is available to export.");
  assertEncryptedWalletRecord(record);
  return JSON.stringify(record, null, 2);
}

export async function importEncryptedWallet(
  contents: string,
  password: string,
): Promise<UnlockedWallet> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(contents) as unknown;
  } catch {
    throw new Error("Invalid encrypted key file.");
  }
  assertEncryptedWalletRecord(parsed);
  let verified: Awaited<ReturnType<typeof decryptAndVerifyWallet>>;
  try {
    verified = await decryptAndVerifyWallet(parsed, password);
  } catch {
    throw new Error("The wallet password or key file is invalid.");
  }
  const record =
    parsed.format === LEGACY_WALLET_FORMAT
      ? await encryptWalletRecord(
          password,
          verified.privateJwk,
          verified.identity,
          parsed.createdAt,
        )
      : parsed;
  await putRecord(record);
  return {
    address: verified.identity.address,
    publicKey: verified.identity.publicKey,
    privateKey: verified.identity.privateKey,
    createdAt: record.createdAt,
  };
}

function assertEncryptedWalletRecord(
  value: unknown,
): asserts value is EncryptedWalletRecord {
  if (!value || typeof value !== "object") {
    throw new Error("Invalid encrypted key file.");
  }
  const record = value as Partial<EncryptedWalletRecord>;
  const publicKeyJwk = record.publicKeyJwk;
  if (
    (record.format !== CURRENT_WALLET_FORMAT &&
      record.format !== LEGACY_WALLET_FORMAT) ||
    record.cipher !== "AES-GCM-256" ||
    record.kdf?.name !== "PBKDF2" ||
    record.kdf.hash !== "SHA-256" ||
    record.kdf.iterations !== PBKDF2_ITERATIONS ||
    typeof record.address !== "string" ||
    !/^[0-9a-f]{64}$/.test(record.address) ||
    typeof record.publicKey !== "string" ||
    !publicKeyJwk ||
    publicKeyJwk.kty !== "EC" ||
    publicKeyJwk.crv !== "P-256" ||
    typeof publicKeyJwk.x !== "string" ||
    typeof publicKeyJwk.y !== "string" ||
    typeof publicKeyJwk.d !== "undefined" ||
    typeof record.ciphertext !== "string" ||
    typeof record.iv !== "string" ||
    typeof record.salt !== "string" ||
    typeof record.createdAt !== "string"
  ) {
    throw new Error("Unsupported or malformed encrypted key file.");
  }
  try {
    const publicKey = base64UrlToBytes(record.publicKey);
    if (
      publicKey.length !== 33 ||
      (publicKey[0] !== 0x02 && publicKey[0] !== 0x03) ||
      base64UrlToBytes(publicKeyJwk.x).length !== 32 ||
      base64UrlToBytes(publicKeyJwk.y).length !== 32 ||
      base64UrlToBytes(record.iv).length !== 12 ||
      base64UrlToBytes(record.salt).length !== 16 ||
      base64UrlToBytes(record.ciphertext).length < 17
    ) {
      throw new Error("invalid wallet field length");
    }
  } catch {
    throw new Error("Unsupported or malformed encrypted key file.");
  }
}

function u16(value: number): Uint8Array {
  if (!Number.isSafeInteger(value) || value < 0 || value > 65_535) {
    throw new Error("Transfer field is too large.");
  }
  return Uint8Array.of((value >>> 8) & 0xff, value & 0xff);
}

function u64(value: bigint): Uint8Array {
  if (value < 0n || value > 18_446_744_073_709_551_615n) {
    throw new Error("Transfer number is outside uint64.");
  }
  const output = new Uint8Array(8);
  let remaining = value;
  for (let index = 7; index >= 0; index -= 1) {
    output[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return output;
}

function sized(value: string): Uint8Array {
  const bytes = encoder.encode(value);
  return concat(u16(bytes.length), bytes);
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const length = parts.reduce((total, part) => total + part.length, 0);
  const output = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.length;
  }
  return output;
}

export function canonicalTransferBytes(
  wallet: Pick<UnlockedWallet, "address" | "publicKey">,
  draft: TransferDraft,
): Uint8Array {
  const publicKey = base64UrlToBytes(wallet.publicKey);
  if (
    publicKey.length !== 33 ||
    (publicKey[0] !== 0x02 && publicKey[0] !== 0x03)
  ) {
    throw new Error("Wallet public key is not compressed SEC1 P-256.");
  }
  return concat(
    encoder.encode("EPDN"),
    Uint8Array.of(6),
    u16(1),
    Uint8Array.of(1),
    sized(draft.chainId),
    publicKey,
    hexToBytes(wallet.address),
    hexToBytes(draft.recipient),
    u64(draft.amount),
    u64(draft.fee),
    u64(draft.nonce),
  );
}

export async function signTransfer(
  wallet: UnlockedWallet,
  draft: TransferDraft,
): Promise<SignedTransfer> {
  const unsigned = canonicalTransferBytes(wallet, draft);
  const signatureInput = concat(
    encoder.encode("EPDN_TRANSFER_SIGNATURE_V1"),
    unsigned,
  );
  const signature = new Uint8Array(
    await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      wallet.privateKey,
      signatureInput,
    ),
  );
  if (signature.length !== 64) {
    throw new Error("The browser did not return an ES256 raw r||s signature.");
  }

  return {
    transaction_hex: bytesToHex(concat(unsigned, u16(signature.length), signature)),
  };
}
