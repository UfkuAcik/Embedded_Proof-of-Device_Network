export const sampleBlocks = [
  { height: 1842, hash: "9c41…aa07", epoch: 98621, winner: "dev_7F2A…91C8", txs: 8, age: "12s" },
  { height: 1841, hash: "1e83…4b2f", epoch: 98620, winner: "dev_B9E4…13A2", txs: 5, age: "42s" },
  { height: 1840, hash: "70d6…e91c", epoch: 98619, winner: "dev_21D0…C41E", txs: 11, age: "1m" },
  { height: 1839, hash: "c3a2…9f44", epoch: 98618, winner: "dev_7F2A…91C8", txs: 4, age: "2m" },
  { height: 1838, hash: "f0b1…7d9e", epoch: 98617, winner: "dev_4A76…8BE0", txs: 6, age: "2m" },
];

export const sampleMiners = [
  {
    id: "dev_7F2A91C8",
    name: "Bench ESP32",
    board: "Classic ESP32 · synthetic demo",
    firmware: "miner 0.1.0 · a6d8…c9e1",
    security: "L0 · DEVELOPMENT",
    status: "online",
    lastSeen: "8 sec ago",
    uptime: "18h 42m",
    accepted: 1428,
    rejected: 3,
    wins: 46,
    reward: "184.00 EPDN",
    heap: "142 KB",
    rssi: "−54 dBm",
  },
  {
    id: "dev_B9E413A2",
    name: "Gateway Lab Unit",
    board: "UART gateway · simulated",
    firmware: "gateway 0.1.0 · 20c4…28de",
    security: "L0 · DEVELOPMENT",
    status: "offline",
    lastSeen: "14 min ago",
    uptime: "6h 09m",
    accepted: 612,
    rejected: 1,
    wins: 19,
    reward: "76.00 EPDN",
    heap: "—",
    rssi: "—",
  },
];

export const rewardSeries: Record<string, number[]> = {
  "24h": [1, 2, 1, 3, 2, 4, 3, 5, 3, 4, 6, 4],
  "7d": [8, 12, 10, 15, 18, 16, 21],
  "30d": [20, 24, 18, 31, 28, 36, 42, 39, 48, 43, 52, 57],
  "90d": [28, 34, 31, 43, 47, 41, 52, 61, 58, 70, 66, 78],
  all: [12, 19, 28, 33, 48, 61, 76, 94, 115, 139, 162, 184],
};

export const sampleEvents = [
  { kind: "BLOCK", detail: "#1,842 finalized", time: "12 sec" },
  { kind: "TICKET", detail: "dev_7F2A accepted", time: "18 sec" },
  { kind: "EPOCH", detail: "98,621 opened", time: "30 sec" },
  { kind: "REWARD", detail: "+4.00 EPDN assigned", time: "42 sec" },
];
