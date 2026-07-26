function readList(value, key) {
  if (Array.isArray(value)) return value;
  if (value && typeof value === "object") {
    const candidate = value[key];
    return Array.isArray(candidate) ? candidate : null;
  }
  return null;
}

function finiteNumber(value, fallback = 0) {
  const number = Number(value);
  return Number.isFinite(number) ? number : fallback;
}

export function hexFromUnknown(value) {
  if (typeof value === "string") return value;
  if (
    Array.isArray(value) &&
    value.length > 0 &&
    value.every(
      (byte) => Number.isInteger(byte) && byte >= 0 && byte <= 255,
    )
  ) {
    return value.map((byte) => byte.toString(16).padStart(2, "0")).join("");
  }
  return "";
}

export function normalizeBlocks(value) {
  const rows = readList(value, "blocks");
  if (!rows) return null;

  return rows
    .map((row, index) => {
      const item = row && typeof row === "object" ? row : {};
      const header =
        item.header && typeof item.header === "object" ? item.header : item;
      const transactions = Array.isArray(item.transactions)
        ? item.transactions.length
        : finiteNumber(item.transaction_count ?? item.txs);

      return {
        height: finiteNumber(header.height ?? item.height),
        hash:
          hexFromUnknown(item.block_hash ?? item.hash) || `block-${index}`,
        epoch: finiteNumber(
          header.epoch_number ??
            header.epoch ??
            item.epoch_number ??
            item.epoch,
        ),
        winner:
          hexFromUnknown(
            header.winning_device_public_key_hash ??
              item.winning_device_public_key_hash ??
              item.winner,
          ) || "unknown",
        txs: transactions,
        age: String(item.age ?? "finalized"),
      };
    })
    .sort((left, right) => right.height - left.height)
    .slice(0, 8);
}

export function normalizeMiners(value) {
  const rows = readList(value, "miners");
  if (!rows) return null;

  return rows.slice(0, 12).map((row, index) => {
    const item = row && typeof row === "object" ? row : {};
    const platform = String(item.platform ?? "embedded").toLowerCase();
    const boardFamily = String(item.board_family ?? "board family not exposed");
    const status = item.revoked
      ? "revoked"
      : item.paused
        ? "paused"
        : String(item.status ?? "registered");

    return {
      id: String(item.public_id ?? item.id ?? `miner-${index}`),
      name: String(
        item.name ??
          `Provisioned ${platform.toUpperCase()} identity`,
      ),
      board: String(
        item.board_model ?? `${platform} · ${boardFamily}`,
      ),
      firmware: String(
        item.firmware_version ??
          (item.firmware_id
            ? hexFromUnknown(item.firmware_id)
            : "certificate-bound firmware"),
      ),
      security: String(item.security_class ?? "UNVERIFIED"),
      status,
      lastSeen: String(item.last_seen ?? "not exposed"),
      uptime: String(item.uptime ?? "not exposed"),
      accepted: finiteNumber(item.accepted_tickets),
      rejected: finiteNumber(item.rejected_tickets),
      wins: finiteNumber(item.won_epochs),
      reward: `${String(item.total_reward ?? "0")} EPDN`,
      heap: String(item.free_heap ?? "—"),
      rssi: String(item.wifi_rssi ?? "—"),
    };
  });
}

export function normalizeNetworkStatus(value) {
  if (!value || typeof value !== "object") return null;

  const height = finiteNumber(value.height, Number.NaN);
  const currentEpoch = finiteNumber(value.current_epoch, Number.NaN);
  const registeredDevices = finiteNumber(
    value.registered_devices,
    Number.NaN,
  );
  const acceptedTickets = finiteNumber(value.accepted_tickets);
  if (
    !Number.isSafeInteger(height) ||
    height < 0 ||
    !Number.isSafeInteger(currentEpoch) ||
    currentEpoch < 0 ||
    !Number.isSafeInteger(registeredDevices) ||
    registeredDevices < 0
  ) {
    return null;
  }

  return {
    height,
    currentEpoch,
    registeredDevices,
    acceptedTickets,
    networkMode: String(value.network_mode ?? "unknown"),
    randomnessSource: String(value.randomness_source ?? "not exposed"),
    protocolVersion: finiteNumber(value.protocol_version),
  };
}
