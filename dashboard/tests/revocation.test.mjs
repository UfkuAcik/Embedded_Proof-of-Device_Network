import assert from "node:assert/strict";
import test from "node:test";

import {
  MAX_REVOCATION_REASON_BYTES,
  normalizeRevocationReason,
} from "../app/lib/revocation.mjs";

test("revocation reasons are capped at 128 UTF-8 bytes", () => {
  assert.equal(MAX_REVOCATION_REASON_BYTES, 128);
  assert.equal(normalizeRevocationReason(`  ${"a".repeat(128)}  `), "a".repeat(128));
  assert.equal(normalizeRevocationReason("a".repeat(129)), null);
  assert.equal(normalizeRevocationReason("ş".repeat(64)), "ş".repeat(64));
  assert.equal(normalizeRevocationReason(`${"ş".repeat(64)}a`), null);
  assert.equal(normalizeRevocationReason("abc"), null);
});
