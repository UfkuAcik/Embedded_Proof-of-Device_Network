import assert from "node:assert/strict";
import test from "node:test";

import {
  hexFromUnknown,
  normalizeBlocks,
  normalizeMiners,
  normalizeNetworkStatus,
} from "../app/lib/api-normalizers.mjs";

const bytes = (start = 0) =>
  Array.from({ length: 32 }, (_, index) => (start + index) % 256);

test("normalizes the validator's nested block wire shape and newest-first order", () => {
  const rows = normalizeBlocks([
    {
      header: {
        height: 5,
        epoch_number: 6,
        winning_device_public_key_hash: bytes(32),
      },
      block_hash: bytes(0),
      transactions: [{ kind: "reward_distribution" }],
    },
    {
      header: {
        height: 6,
        epoch_number: 7,
        winning_device_public_key_hash: bytes(64),
      },
      block_hash: bytes(96),
      transactions: [],
    },
  ]);

  assert.equal(rows.length, 2);
  assert.equal(rows[0].height, 6);
  assert.equal(rows[0].epoch, 7);
  assert.equal(rows[0].hash, hexFromUnknown(bytes(96)));
  assert.equal(rows[1].winner, hexFromUnknown(bytes(32)));
  assert.equal(rows[1].txs, 1);
  assert.equal(rows[1].age, "finalized");
});

test("maps registry flags without inventing liveness or board models", () => {
  const [miner] = normalizeMiners([
    {
      public_id: "f".repeat(64),
      platform: "esp32",
      board_family: "esp32-classic-generic",
      security_class: "L0_SOFTWARE_TEST",
      revoked: true,
      paused: false,
    },
  ]);

  assert.equal(miner.status, "revoked");
  assert.equal(miner.board, "esp32 · esp32-classic-generic");
  assert.equal(miner.lastSeen, "not exposed");
  assert.equal(miner.firmware, "certificate-bound firmware");
});

test("accepts complete network status and rejects incomplete live schemas", () => {
  assert.deepEqual(
    normalizeNetworkStatus({
      height: 6,
      current_epoch: 7,
      registered_devices: 6,
      accepted_tickets: 0,
      network_mode: "testnet",
      randomness_source: "insecure_single_node_development",
      protocol_version: 1,
    }),
    {
      height: 6,
      currentEpoch: 7,
      registeredDevices: 6,
      acceptedTickets: 0,
      networkMode: "testnet",
      randomnessSource: "insecure_single_node_development",
      protocolVersion: 1,
    },
  );
  assert.equal(normalizeNetworkStatus({ height: 6 }), null);
});
