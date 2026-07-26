"use client";

import QRCode from "qrcode";
import Image from "next/image";
import {
  FormEvent,
  useCallback,
  useEffect,
  useRef,
  useState,
} from "react";
import {
  createEncryptedWallet,
  exportEncryptedWallet,
  importEncryptedWallet,
  loadEncryptedWallet,
  signTransfer,
  unlockEncryptedWallet,
  type UnlockedWallet,
} from "./lib/wallet";
import {
  fetchWalletAccountState,
  type WalletAccountState,
} from "./lib/account";
import {
  MAX_REVOCATION_REASON_BYTES,
  normalizeRevocationReason,
} from "./lib/revocation.mjs";
import {
  rewardSeries,
  sampleBlocks,
  sampleEvents,
  sampleMiners,
} from "./lib/sample-data";
import {
  normalizeBlocks,
  normalizeMiners,
  normalizeNetworkStatus,
} from "./lib/api-normalizers.mjs";
import { PwaRegistration } from "./pwa-registration";

type View = "explorer" | "dashboard" | "wallet";
type Range = "24h" | "7d" | "30d" | "90d" | "all";
type WalletStorageState = "loading" | "absent" | "present" | "error";
type Viewer = { displayName: string; signedIn: boolean };
type StreamEvent = { kind: string; detail: string; time: string };
type Block = (typeof sampleBlocks)[number];
type Miner = (typeof sampleMiners)[number];
type NetworkStatus = {
  height: number;
  currentEpoch: number;
  registeredDevices: number;
  acceptedTickets: number;
  networkMode: string;
  randomnessSource: string;
  protocolVersion: number;
};

const sampleNetworkStatus: NetworkStatus = {
  height: 1842,
  currentEpoch: 98621,
  registeredDevices: 128,
  acceptedTickets: 2040,
  networkMode: "deterministic_demo",
  randomnessSource: "commit_reveal_sample",
  protocolVersion: 1,
};

const ranges: { id: Range; label: string }[] = [
  { id: "24h", label: "24H" },
  { id: "7d", label: "7D" },
  { id: "30d", label: "30D" },
  { id: "90d", label: "90D" },
  { id: "all", label: "ALL" },
];

const apiEventKinds = [
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
] as const;

function compact(value: number): string {
  return new Intl.NumberFormat("en", { notation: "compact" }).format(value);
}

function shortId(value: string): string {
  return value.length > 24
    ? `${value.slice(0, 12)}…${value.slice(-10)}`
    : value;
}

function parseProtocolUnits(value: string): bigint {
  const normalized = value.trim();
  if (!/^(0|[1-9]\d*)$/.test(normalized)) {
    throw new Error("Use whole EPDN testnet units.");
  }
  const result = BigInt(normalized);
  if (result > 18_446_744_073_709_551_615n) {
    throw new Error("Transfer amount is outside the protocol range.");
  }
  return result;
}

function protocolUnitTotal(amount: string, fee: string): string {
  try {
    return (parseProtocolUnits(amount) + parseProtocolUnits(fee)).toString();
  } catch {
    return "—";
  }
}

function barHeightClass(value: number, maximum: number): string {
  const ratio = maximum > 0 ? value / maximum : 0;
  const bucket = Math.max(1, Math.min(10, Math.ceil(ratio * 10)));
  return `bar-height-${bucket}`;
}

function apiEventDetail(kind: string, payload: unknown): string {
  if (payload && typeof payload === "object") {
    const fields = payload as Record<string, unknown>;
    for (const key of [
      "detail",
      "hash",
      "transaction_hash",
      "public_id",
      "device_public_id",
      "height",
      "epoch",
      "address",
      "skipped",
    ]) {
      const value = fields[key];
      if (typeof value === "string" || typeof value === "number") {
        return `${key}: ${String(value)}`.slice(0, 120);
      }
    }
  }
  if (typeof payload === "string") return payload.slice(0, 120);
  return kind;
}

type LiveSnapshot = {
  blocks: Block[];
  miners: Miner[];
  networkStatus: NetworkStatus;
  chainId: string | null;
};

async function fetchLiveSnapshot(
  baseUrl: string,
  signal: AbortSignal,
): Promise<LiveSnapshot> {
  const [statusResponse, blockResponse, minerResponse] = await Promise.all([
    fetch(`${baseUrl}/api/v1/network/status`, {
      signal,
      cache: "no-store",
    }),
    fetch(`${baseUrl}/api/v1/blocks`, {
      signal,
      cache: "no-store",
    }),
    fetch(`${baseUrl}/api/v1/miners`, {
      signal,
      cache: "no-store",
    }),
  ]);
  if (!statusResponse.ok || !blockResponse.ok || !minerResponse.ok) {
    throw new Error("Validator API returned an error.");
  }
  const [statusPayload, blockPayload, minerPayload] = await Promise.all([
    statusResponse.json(),
    blockResponse.json(),
    minerResponse.json(),
  ]);
  const blocks = normalizeBlocks(blockPayload) as Block[] | null;
  const miners = normalizeMiners(minerPayload) as Miner[] | null;
  const networkStatus = normalizeNetworkStatus(
    statusPayload,
  ) as NetworkStatus | null;
  if (!blocks || !miners || !networkStatus) {
    throw new Error("Validator API schema was not recognized.");
  }
  const status = statusPayload as Record<string, unknown>;
  const rawChainId = status.chain_id ?? status.network_id;
  return {
    blocks,
    miners,
    networkStatus,
    chainId: typeof rawChainId === "string" ? rawChainId : null,
  };
}

export function EpdnApp({ viewer }: { viewer: Viewer }) {
  const [view, setView] = useState<View>("explorer");
  const [theme, setTheme] = useState<"dark" | "light">("dark");
  const [range, setRange] = useState<Range>("7d");
  const [apiBase, setApiBase] = useState("");
  const [apiInput, setApiInput] = useState("");
  const [chainId, setChainId] = useState("epdn-local-testnet-v1");
  const [source, setSource] = useState<"checking" | "demo" | "live">("checking");
  const [stream, setStream] = useState<"idle" | "connecting" | "live" | "retrying">("idle");
  const [blocks, setBlocks] = useState<Block[]>(sampleBlocks);
  const [miners, setMiners] = useState<Miner[]>(sampleMiners);
  const [events, setEvents] = useState<StreamEvent[]>(sampleEvents);
  const [networkStatus, setNetworkStatus] =
    useState<NetworkStatus>(sampleNetworkStatus);
  const [notice, setNotice] = useState("");
  const [revokeTarget, setRevokeTarget] = useState<Miner | null>(null);
  const [revokeReason, setRevokeReason] = useState("Device retired");
  const [walletStorageState, setWalletStorageState] =
    useState<WalletStorageState>("loading");
  const [walletRecordAddress, setWalletRecordAddress] = useState("");
  const [wallet, setWallet] = useState<UnlockedWallet | null>(null);
  const [walletAccount, setWalletAccount] =
    useState<WalletAccountState | null>(null);
  const [walletPassword, setWalletPassword] = useState("");
  const [walletBusy, setWalletBusy] = useState(false);
  const [walletMessage, setWalletMessage] = useState("");
  const [qrData, setQrData] = useState("");
  const [recipient, setRecipient] = useState("");
  const [amount, setAmount] = useState("4");
  const [fee, setFee] = useState("0");
  const [showApiSettings, setShowApiSettings] = useState(false);
  const streamRef = useRef<EventSource | null>(null);
  const transferInFlightRef = useRef(false);
  const connectionGenerationRef = useRef(0);
  const connectionAbortRef = useRef<AbortController | null>(null);
  const refreshAbortRef = useRef<AbortController | null>(null);

  const connect = useCallback(async (base: string) => {
    const generation = connectionGenerationRef.current + 1;
    connectionGenerationRef.current = generation;
    connectionAbortRef.current?.abort();
    refreshAbortRef.current?.abort();
    streamRef.current?.close();
    const normalized = base.trim().replace(/\/$/, "");
    if (!normalized) {
      setApiBase("");
      setSource("demo");
      setStream("idle");
      setBlocks(sampleBlocks);
      setMiners(sampleMiners);
      setEvents(sampleEvents);
      setNetworkStatus(sampleNetworkStatus);
      return;
    }

    setSource("checking");
    const controller = new AbortController();
    connectionAbortRef.current = controller;
    const timeout = window.setTimeout(() => controller.abort(), 4_000);
    try {
      const snapshot = await fetchLiveSnapshot(normalized, controller.signal);
      if (generation !== connectionGenerationRef.current) return;
      if (snapshot.chainId) setChainId(snapshot.chainId);
      setBlocks(snapshot.blocks);
      setMiners(snapshot.miners);
      setNetworkStatus(snapshot.networkStatus);
      setEvents([]);
      setApiBase(normalized);
      setApiInput(normalized);
      setSource("live");
      setStream("connecting");

      const eventSource = new EventSource(`${normalized}/api/v1/events`);
      streamRef.current = eventSource;
      const isCurrent = () =>
        generation === connectionGenerationRef.current &&
        streamRef.current === eventSource;
      let refreshRunning = false;
      let refreshQueued = false;
      const refreshLiveState = async () => {
        refreshQueued = true;
        if (refreshRunning) return;
        refreshRunning = true;
        while (refreshQueued && isCurrent()) {
          refreshQueued = false;
          const refreshController = new AbortController();
          refreshAbortRef.current = refreshController;
          try {
            const refreshed = await fetchLiveSnapshot(
              normalized,
              refreshController.signal,
            );
            if (!isCurrent()) return;
            if (refreshed.chainId) setChainId(refreshed.chainId);
            setBlocks(refreshed.blocks);
            setMiners(refreshed.miners);
            setNetworkStatus(refreshed.networkStatus);
          } catch {
            if (!refreshController.signal.aborted && isCurrent()) {
              setNotice("A live event arrived, but the data refresh failed.");
            }
          } finally {
            if (refreshAbortRef.current === refreshController) {
              refreshAbortRef.current = null;
            }
          }
        }
        refreshRunning = false;
      };
      eventSource.onopen = () => {
        if (isCurrent()) setStream("live");
      };
      eventSource.onerror = () => {
        if (isCurrent()) setStream("retrying");
      };
      const receive = (eventKind: string) => (event: MessageEvent<string>) => {
        if (!isCurrent()) return;
        let kind = eventKind;
        let detail = event.data;
        try {
          const parsed = JSON.parse(event.data) as Record<string, unknown>;
          if (typeof parsed.kind === "string" && parsed.kind === eventKind) {
            kind = parsed.kind;
          }
          const payload =
            Object.hasOwn(parsed, "payload") ? parsed.payload : parsed;
          detail = apiEventDetail(kind, payload);
        } catch {
          detail = event.data.slice(0, 120);
        }
        setEvents((current) =>
          [{ kind, detail, time: "now" }, ...current].slice(0, 8),
        );
        void refreshLiveState();
      };
      for (const kind of apiEventKinds) {
        eventSource.addEventListener(kind, receive(kind));
      }
    } catch {
      if (
        controller.signal.aborted ||
        generation !== connectionGenerationRef.current
      ) {
        return;
      }
      setApiBase(normalized);
      setApiInput(normalized);
      setSource("demo");
      setStream("idle");
      setBlocks(sampleBlocks);
      setMiners(sampleMiners);
      setEvents(sampleEvents);
      setNetworkStatus(sampleNetworkStatus);
      setNotice("Validator unavailable — deterministic demo data is on screen.");
    } finally {
      window.clearTimeout(timeout);
      if (connectionAbortRef.current === controller) {
        connectionAbortRef.current = null;
      }
    }
  }, []);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
  }, [theme]);

  useEffect(() => {
    const setupController = new AbortController();
    let disposed = false;
    void fetch("/api/config", {
      cache: "no-store",
      signal: setupController.signal,
    })
      .then((response) => response.json())
      .then((config: { apiBaseUrl?: string; chainId?: string }) => {
        if (disposed) return;
        const base = config.apiBaseUrl ?? "";
        setChainId(config.chainId ?? "epdn-local-testnet-v1");
        setApiInput(base);
        return connect(base);
      })
      .catch(() => {
        if (!disposed) return connect("");
      });
    void loadEncryptedWallet()
      .then((record) => {
        if (disposed) return;
        setWalletStorageState(record === null ? "absent" : "present");
        setWalletRecordAddress("");
      })
      .catch(() => {
        if (!disposed) {
          setWalletStorageState("error");
          setWalletMessage("Encrypted wallet storage is unavailable.");
        }
      });
    return () => {
      disposed = true;
      setupController.abort();
      connectionGenerationRef.current += 1;
      connectionAbortRef.current?.abort();
      refreshAbortRef.current?.abort();
      streamRef.current?.close();
    };
  }, [connect]);

  useEffect(() => {
    if (!wallet) return;
    const lock = () => {
      setWallet(null);
      setWalletMessage("Wallet locked after 5 minutes of inactivity.");
    };
    let timeout = window.setTimeout(lock, 5 * 60 * 1_000);
    const renew = () => {
      window.clearTimeout(timeout);
      timeout = window.setTimeout(lock, 5 * 60 * 1_000);
    };
    window.addEventListener("pointerdown", renew, { passive: true });
    window.addEventListener("keydown", renew);
    return () => {
      window.clearTimeout(timeout);
      window.removeEventListener("pointerdown", renew);
      window.removeEventListener("keydown", renew);
    };
  }, [wallet]);

  useEffect(() => {
    const address = wallet?.address ?? walletRecordAddress;
    if (!address) return;
    void QRCode.toDataURL(address, {
      width: 220,
      margin: 1,
      errorCorrectionLevel: "M",
      color: { dark: "#07100e", light: "#f7fbf6" },
    }).then(setQrData);
  }, [wallet, walletRecordAddress]);

  useEffect(() => {
    const address = wallet?.address ?? walletRecordAddress;
    if (!address || !apiBase || source !== "live") {
      return;
    }

    const controller = new AbortController();
    void fetchWalletAccountState(apiBase, address, fetch, controller.signal)
      .then(setWalletAccount)
      .catch((error: unknown) => {
        if (!(error instanceof DOMException && error.name === "AbortError")) {
          setWalletAccount(null);
        }
      });
    return () => controller.abort();
  }, [apiBase, source, wallet, walletRecordAddress]);

  const chart =
    source === "live"
      ? rewardSeries[range].map(() => 0)
      : rewardSeries[range];
  const maxChart = Math.max(...chart);
  const onlineCount = miners.filter((miner) => miner.status === "online").length;
  const totalAccepted = miners.reduce((sum, miner) => sum + miner.accepted, 0);
  const totalRewards = miners.reduce(
    (sum, miner) => sum + Number.parseFloat(miner.reward),
    0,
  );

  async function handleWalletCreate(event: FormEvent) {
    event.preventDefault();
    if (walletStorageState !== "absent") {
      setWalletMessage("Wallet storage must be checked before creating a wallet.");
      return;
    }
    setWalletBusy(true);
    setWalletMessage("");
    try {
      const unlocked = await createEncryptedWallet(walletPassword);
      setWallet(unlocked);
      setWalletStorageState("present");
      setWalletRecordAddress(unlocked.address);
      setWalletPassword("");
      setWalletMessage("Wallet created and encrypted locally.");
    } catch (error) {
      setWalletMessage(error instanceof Error ? error.message : "Wallet creation failed.");
    } finally {
      setWalletBusy(false);
    }
  }

  async function handleUnlock(event: FormEvent) {
    event.preventDefault();
    setWalletBusy(true);
    setWalletMessage("");
    try {
      const unlocked = await unlockEncryptedWallet(walletPassword);
      setWallet(unlocked);
      setWalletStorageState("present");
      setWalletRecordAddress(unlocked.address);
      setWalletPassword("");
      setWalletMessage("Wallet unlocked in memory. Auto-lock is active.");
    } catch (error) {
      setWalletMessage(error instanceof Error ? error.message : "Unlock failed.");
    } finally {
      setWalletBusy(false);
    }
  }

  async function handleExport() {
    try {
      const contents = await exportEncryptedWallet();
      const link = document.createElement("a");
      link.href = URL.createObjectURL(
        new Blob([contents], { type: "application/json" }),
      );
      link.download = `epdn-wallet-${walletRecordAddress.slice(0, 12) || "encrypted"}.json`;
      link.click();
      URL.revokeObjectURL(link.href);
      setWalletMessage("Encrypted key file exported. Keep it offline.");
    } catch (error) {
      setWalletMessage(error instanceof Error ? error.message : "Export failed.");
    }
  }

  async function handleImport(file: File | undefined) {
    if (
      walletStorageState !== "absent" &&
      walletStorageState !== "present"
    ) {
      setWalletMessage("Wallet storage must be checked before importing a wallet.");
      return;
    }
    if (!file || file.size > 128_000) {
      setWalletMessage("Choose an EPDN encrypted key file under 128 KB.");
      return;
    }
    if (!walletPassword) {
      setWalletMessage(
        "Enter the imported wallet's password before selecting its file.",
      );
      return;
    }
    setWalletBusy(true);
    try {
      const imported = await importEncryptedWallet(
        await file.text(),
        walletPassword,
      );
      setWallet(imported);
      setWalletStorageState("present");
      setWalletRecordAddress(imported.address);
      setWalletAccount(null);
      setWalletPassword("");
      setWalletMessage(
        "Wallet identity verified, imported, and unlocked in memory. Auto-lock is active.",
      );
    } catch (error) {
      setWalletMessage(error instanceof Error ? error.message : "Import failed.");
    } finally {
      setWalletBusy(false);
    }
  }

  async function handleSend(event: FormEvent) {
    event.preventDefault();
    if (!wallet || transferInFlightRef.current) return;
    if (!/^[0-9a-f]{64}$/.test(recipient)) {
      setWalletMessage("Check the EPDN recipient address before signing.");
      return;
    }
    transferInFlightRef.current = true;
    setWalletBusy(true);
    try {
      const amountUnits = parseProtocolUnits(amount);
      const feeUnits = parseProtocolUnits(fee);
      if (amountUnits <= 0n) {
        throw new Error("Amount must be greater than zero.");
      }
      let nonce = 0n;
      if (apiBase && source === "live") {
        const account = await fetchWalletAccountState(apiBase, wallet.address);
        setWalletAccount(account);
        nonce = account.nextNonce;
      }
      const envelope = await signTransfer(wallet, {
        chainId,
        recipient,
        amount: amountUnits,
        fee: feeUnits,
        nonce,
      });
      if (!apiBase || source !== "live") {
        setWalletMessage(
          "Transaction signed locally. Demo mode never broadcasts transactions.",
        );
        return;
      }
      const response = await fetch(`${apiBase}/api/v1/transactions`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(envelope),
      });
      if (!response.ok) {
        const rejected = (await response.json().catch(() => ({}))) as {
          error?: unknown;
          message?: unknown;
        };
        if (response.status === 409 && rejected.error === "wrong_nonce") {
          const refreshed = await fetchWalletAccountState(apiBase, wallet.address);
          setWalletAccount(refreshed);
          throw new Error(
            "The account nonce changed before broadcast. Review and submit again.",
          );
        }
        throw new Error(
          typeof rejected.message === "string"
            ? rejected.message
            : "Validator rejected the transaction.",
        );
      }
      let refreshWarning = "";
      try {
        setWalletAccount(
          await fetchWalletAccountState(apiBase, wallet.address),
        );
      } catch {
        refreshWarning = " Account refresh is pending.";
      }
      setWalletMessage(
        `Signed transaction broadcast to the validator.${refreshWarning}`,
      );
      setRecipient("");
    } catch (error) {
      setWalletMessage(error instanceof Error ? error.message : "Transaction failed.");
    } finally {
      transferInFlightRef.current = false;
      setWalletBusy(false);
    }
  }

  async function handleRevoke(event: FormEvent) {
    event.preventDefault();
    if (!revokeTarget) return;
    setNotice("");
    const normalizedReason = normalizeRevocationReason(revokeReason);
    if (!normalizedReason) {
      setNotice(
        `Revocation reason must be 4-${MAX_REVOCATION_REASON_BYTES} UTF-8 bytes.`,
      );
      return;
    }
    const response = await fetch("/api/admin/revoke", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        publicId: revokeTarget.id,
        reason: normalizedReason,
      }),
    });
    const payload = (await response.json().catch(() => ({}))) as {
      error?: string;
    };
    if (!response.ok) {
      setNotice(payload.error ?? "Revocation request failed.");
      return;
    }
    setNotice(`Revocation submitted for ${revokeTarget.id}.`);
    setRevokeTarget(null);
  }

  function copyAddress() {
    const address = wallet?.address ?? walletRecordAddress;
    if (!address) return;
    void navigator.clipboard.writeText(address).then(() => {
      setWalletMessage(
        `Copied ${address.slice(0, 10)}…${address.slice(-8)}. Verify both ends before use.`,
      );
    });
  }

  return (
    <div className="app-shell">
      <PwaRegistration />
      <header className="topbar">
        <button
          className="brand"
          onClick={() => setView("explorer")}
          aria-label="EPDN public explorer"
        >
          <span className="brand-mark" aria-hidden="true">
            <i />
            <i />
            <i />
          </span>
          <span>
            <b>EPDN</b>
            <small>PROOF OF DEVICE NETWORK</small>
          </span>
        </button>
        <div className="network-cluster">
          <span className={`source-badge ${source}`}>
            {source === "live" ? "LIVE" : source === "checking" ? "CHECKING" : "DEMO"}
          </span>
          <span className="network-name">{chainId}</span>
          <button
            className="icon-button"
            onClick={() => setShowApiSettings((current) => !current)}
            aria-expanded={showApiSettings}
            aria-label="Configure validator API"
          >
            API
          </button>
          <button
            className="icon-button"
            onClick={() => setTheme(theme === "dark" ? "light" : "dark")}
            aria-label={`Switch to ${theme === "dark" ? "light" : "dark"} mode`}
          >
            {theme === "dark" ? "☼" : "◐"}
          </button>
        </div>
      </header>

      {showApiSettings && (
        <form
          className="api-settings"
          onSubmit={(event) => {
            event.preventDefault();
            setShowApiSettings(false);
            void connect(apiInput);
          }}
        >
          <label htmlFor="api-base">Validator REST API base URL</label>
          <div>
            <input
              id="api-base"
              type="url"
              inputMode="url"
              placeholder="http://127.0.0.1:8080"
              value={apiInput}
              onChange={(event) => setApiInput(event.target.value)}
            />
            <button className="primary-button" type="submit">
              Connect
            </button>
          </div>
          <p>Kept in memory for this session. Empty uses deterministic demo data.</p>
        </form>
      )}

      <nav className="product-nav" aria-label="EPDN surfaces">
        <div className="nav-group public-group">
          <span>PUBLIC</span>
          <button
            className={view === "explorer" ? "active" : ""}
            onClick={() => setView("explorer")}
            aria-current={view === "explorer" ? "page" : undefined}
          >
            Explorer
          </button>
        </div>
        <div className="nav-divider" aria-hidden="true" />
        <div className="nav-group private-group">
          <span>MY WORKSPACE</span>
          <button
            className={view === "dashboard" ? "active" : ""}
            onClick={() => setView("dashboard")}
            aria-current={view === "dashboard" ? "page" : undefined}
          >
            Miners
          </button>
          <button
            className={view === "wallet" ? "active" : ""}
            onClick={() => setView("wallet")}
            aria-current={view === "wallet" ? "page" : undefined}
          >
            Wallet
          </button>
        </div>
        <div className="viewer">
          <span className={viewer.signedIn ? "avatar signed" : "avatar"}>
            {viewer.displayName.slice(0, 1).toUpperCase()}
          </span>
          <div>
            <b>{viewer.displayName}</b>
            {viewer.signedIn ? (
              <a href="/signout-with-chatgpt?return_to=%2F">Sign out</a>
            ) : (
              <a href="/signin-with-chatgpt?return_to=%2F">Sign in for writes</a>
            )}
          </div>
        </div>
      </nav>

      {source === "demo" && (
        <div className="demo-strip" role="status">
          <b>DEMO DATA</b>
          <span>
            The validator API is unavailable. Figures are deterministic samples;
            no chain action will be simulated as real.
          </span>
        </div>
      )}

      <main id="main-content">
        {notice && (
          <div className="notice" role="status">
            {notice}
            <button onClick={() => setNotice("")} aria-label="Dismiss message">
              ×
            </button>
          </div>
        )}

        {view === "explorer" && (
          <Explorer
            blocks={blocks}
            source={source}
            stream={stream}
            miners={miners}
            networkStatus={networkStatus}
          />
        )}
        {view === "dashboard" && (
          <Dashboard
            miners={miners}
            events={events}
            range={range}
            setRange={setRange}
            chart={chart}
            maxChart={maxChart}
            onlineCount={onlineCount}
            totalAccepted={totalAccepted}
            totalRewards={totalRewards}
            viewer={viewer}
            onRevoke={setRevokeTarget}
            source={source}
            networkStatus={networkStatus}
          />
        )}
        {view === "wallet" && (
          <WalletView
            wallet={wallet}
            walletStorageState={walletStorageState}
            walletRecordAddress={walletRecordAddress}
            password={walletPassword}
            setPassword={setWalletPassword}
            busy={walletBusy}
            message={walletMessage}
            qrData={qrData}
            recipient={recipient}
            setRecipient={setRecipient}
            amount={amount}
            setAmount={setAmount}
            fee={fee}
            setFee={setFee}
            onCreate={handleWalletCreate}
            onUnlock={handleUnlock}
            onLock={() => {
              setWallet(null);
              setWalletMessage("Wallet locked; decrypted key discarded from memory.");
            }}
            onExport={handleExport}
            onImport={handleImport}
            onCopy={copyAddress}
            onSend={handleSend}
            source={source}
            walletBalance={
              walletAccount?.address ===
              (wallet?.address ?? walletRecordAddress)
                ? walletAccount.balance
                : null
            }
          />
        )}
      </main>

      {revokeTarget && (
        <div className="modal-backdrop" role="presentation">
          <section
            className="modal"
            role="dialog"
            aria-modal="true"
            aria-labelledby="revoke-title"
          >
            <span className="danger-kicker">CERTIFICATE CONTROL</span>
            <h2 id="revoke-title">Revoke {revokeTarget.name}?</h2>
            <p>
              New tickets from <code>{revokeTarget.id}</code> will be rejected
              after the validator records this action.
            </p>
            <form onSubmit={handleRevoke}>
              <label htmlFor="revoke-reason">Audit reason</label>
              <input
                id="revoke-reason"
                value={revokeReason}
                minLength={4}
                maxLength={MAX_REVOCATION_REASON_BYTES}
                onChange={(event) => setRevokeReason(event.target.value)}
              />
              <div className="modal-actions">
                <button
                  className="quiet-button"
                  type="button"
                  onClick={() => setRevokeTarget(null)}
                >
                  Cancel
                </button>
                <button className="danger-button" type="submit">
                  Confirm revocation
                </button>
              </div>
            </form>
          </section>
        </div>
      )}
    </div>
  );
}

function Explorer({
  blocks,
  source,
  stream,
  miners,
  networkStatus,
}: {
  blocks: Block[];
  source: string;
  stream: string;
  miners: Miner[];
  networkStatus: NetworkStatus;
}) {
  const live = source === "live";
  const revokedCount = miners.filter((miner) => miner.status === "revoked").length;
  const randomness = networkStatus.randomnessSource
    .replace(/^insecure_/, "")
    .replaceAll("_", " ");
  const securityClasses = [...new Set(miners.map((miner) => miner.security))];
  return (
    <div className="page-frame">
      <section className="explorer-hero">
        <div>
          <span className="eyebrow">PUBLIC CHAIN OBSERVATORY</span>
          <h1>
            Proof,
            <br />
            <em>not power.</em>
          </h1>
          <p>
            EPDN selects one deterministic ticket per provisioned embedded
            identity—without a hash-rate race.
          </p>
          <div className="hero-status">
            <span className="pulse" />
            Epoch {networkStatus.currentEpoch.toLocaleString()} · ticket window
            <b>{live ? "OPEN" : "DEMO SAMPLE"}</b>
          </div>
        </div>
        <div
          className="epoch-orbit"
          aria-label={`Current epoch ${networkStatus.currentEpoch.toLocaleString()}`}
        >
          <div>
            <span>EPOCH</span>
            <strong>{networkStatus.currentEpoch.toLocaleString()}</strong>
            <small>{live ? "OPEN · SUBMIT" : "DEMO · SAMPLE"}</small>
          </div>
        </div>
      </section>

      <section className="metric-grid" aria-label="Network summary">
        <Metric
          label="Finalized height"
          value={`#${networkStatus.height.toLocaleString()}`}
          delta={live ? "persisted journal tip" : "deterministic sample"}
        />
        <Metric
          label="Provisioned devices"
          value={networkStatus.registeredDevices.toLocaleString()}
          delta={live ? `${revokedCount} revoked` : "deterministic sample"}
        />
        <Metric label="Epoch duration" value="30s" delta="protocol default" />
        <Metric
          label="Minted test rewards"
          value={compact(networkStatus.height * 100)}
          delta="EPDN · no monetary value"
        />
      </section>

      <div className="content-grid">
        <section className="panel block-panel">
          <PanelHead
            kicker="LEDGER"
            title="Latest finalized blocks"
            action={`${source === "live" ? stream : "sample stream"}`}
          />
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Height</th>
                  <th>Block hash</th>
                  <th>Epoch</th>
                  <th>Winning device</th>
                  <th>Tx</th>
                  <th>Age</th>
                </tr>
              </thead>
              <tbody>
                {blocks.map((block) => (
                  <tr key={`${block.height}-${block.hash}`}>
                    <td><b>#{block.height.toLocaleString()}</b></td>
                    <td><code title={block.hash}>{shortId(block.hash)}</code></td>
                    <td>{block.epoch.toLocaleString()}</td>
                    <td><code title={block.winner}>{shortId(block.winner)}</code></td>
                    <td>{block.txs}</td>
                    <td>{block.age}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>

        <aside className="panel integrity-panel">
          <PanelHead
            kicker="POPED"
            title="Chain integrity"
            action={live ? "node-reported" : "sample"}
          />
          <div className="integrity-score">
            <strong>{live ? "1 / 1" : "3 / 3"}</strong>
            <span>{live ? "development node" : "sample validators"}</span>
          </div>
          <dl className="definition-list">
            <div><dt>Randomness</dt><dd>{randomness}</dd></div>
            <div><dt>Firmware policy</dt><dd>{live ? "certificate-bound" : "sample policy"}</dd></div>
            <div><dt>Revocations</dt><dd>{revokedCount} applied</dd></div>
            <div>
              <dt>Security class</dt>
              <dd>{securityClasses.join(", ") || "not exposed"}</dd>
            </div>
          </dl>
          <p className="boundary-note">
            Public telemetry is diagnostic only. MAC, IP, Wi-Fi, serial, and
            private device labels are never exposed here.
          </p>
        </aside>
      </div>
    </div>
  );
}

function Dashboard({
  miners,
  events,
  range,
  setRange,
  chart,
  maxChart,
  onlineCount,
  totalAccepted,
  totalRewards,
  viewer,
  onRevoke,
  source,
  networkStatus,
}: {
  miners: Miner[];
  events: StreamEvent[];
  range: Range;
  setRange: (range: Range) => void;
  chart: number[];
  maxChart: number;
  onlineCount: number;
  totalAccepted: number;
  totalRewards: number;
  viewer: Viewer;
  onRevoke: (miner: Miner) => void;
  source: string;
  networkStatus: NetworkStatus;
}) {
  const live = source === "live";
  const revokedCount = miners.filter((miner) => miner.status === "revoked").length;
  const pausedCount = miners.filter((miner) => miner.status === "paused").length;
  return (
    <div className="page-frame">
      <PageHeading
        eyebrow="AUTHORIZED MINER OPERATIONS"
        title="Device command"
        italic="center."
        text="Registry identities, node-exposed security classes, and certificate controls stay clearly separated from public chain telemetry."
        aside={
          viewer.signedIn ? (
            <span className="access-pill secure">WRITE ACCESS</span>
          ) : (
            <span className="access-pill">VIEW ONLY · SIGN IN TO WRITE</span>
          )
        }
      />
      <section className="metric-grid">
        <Metric
          label="Reported miner rewards"
          value={live ? "—" : totalRewards.toFixed(2)}
          unit={live ? undefined : "EPDN"}
          delta={live ? "not exposed by registry" : "deterministic sample"}
        />
        <Metric
          label="Registered identities"
          value={live ? `${networkStatus.registeredDevices}` : `${onlineCount} / ${miners.length}`}
          delta={live ? `${revokedCount} revoked · ${pausedCount} paused` : "deterministic sample"}
        />
        <Metric
          label="Accepted tickets"
          value={compact(live ? networkStatus.acceptedTickets : totalAccepted)}
          delta={live ? "current node state" : "deterministic sample"}
        />
        <Metric
          label="Won epochs"
          value={live ? "—" : `${miners.reduce((sum, item) => sum + item.wins, 0)}`}
          delta={live ? "not exposed by registry" : "deterministic sample"}
        />
      </section>

      <div className="dashboard-grid">
        <section className="panel rewards-panel">
          <PanelHead
            kicker="REWARDS"
            title="Proof rewards"
            action={live ? "not exposed" : `${totalRewards.toFixed(2)} EPDN`}
          />
          <div className="range-tabs" aria-label="Reward chart range">
            {ranges.map((item) => (
              <button
                key={item.id}
                className={range === item.id ? "active" : ""}
                onClick={() => setRange(item.id)}
                aria-pressed={range === item.id}
              >
                {item.label}
              </button>
            ))}
          </div>
          {live ? (
            <p className="boundary-note">
              This validator does not expose a historical reward series.
            </p>
          ) : (
            <>
              <div className="bar-chart" role="img" aria-label={`Reward history for ${range}`}>
                {chart.map((value, index) => (
                  <i
                    key={`${range}-${index}`}
                    className={barHeightClass(value, maxChart)}
                    title={`${value} EPDN`}
                  />
                ))}
              </div>
              <div className="chart-axis"><span>Earlier</span><span>Now</span></div>
            </>
          )}
        </section>

        <aside className="panel event-panel">
          <PanelHead kicker="SSE EVENT FEED" title="Live network" action="auto-retry" />
          <ol className="event-list">
            {events.length === 0 && (
              <li>
                <span>SSE</span>
                <p>Waiting for validator events.</p>
                <time>live</time>
              </li>
            )}
            {events.map((event, index) => (
              <li key={`${event.kind}-${event.time}-${index}`}>
                <span>{event.kind}</span>
                <p>{event.detail}</p>
                <time>{event.time}</time>
              </li>
            ))}
          </ol>
        </aside>
      </div>

      <section className="panel miners-panel">
        <PanelHead kicker="PROVISIONED IDENTITIES" title="My miners" action={`${miners.length} registered`} />
        <div className="miner-list">
          {miners.map((miner) => (
            <article className="miner-row" key={miner.id}>
              <div className="miner-identity">
                <span className={`status-dot ${miner.status}`} />
                <div>
                  <h3>{miner.name}</h3>
                  <code title={miner.id}>{shortId(miner.id)}</code>
                </div>
              </div>
              <div className="miner-primary">
                <span>{miner.board}</span>
                <small>{miner.firmware}</small>
              </div>
              <div className="miner-stats">
                <span><b>{live ? "—" : miner.accepted.toLocaleString()}</b> accepted</span>
                <span><b>{live ? "—" : miner.wins}</b> wins</span>
                <span><b>{live ? "—" : miner.reward}</b> reward</span>
              </div>
              <div className="miner-security">
                <span>{miner.security}</span>
                <small>Seen {miner.lastSeen} · {miner.rssi}</small>
              </div>
              <button
                className="row-action"
                disabled={miner.status === "revoked"}
                onClick={() => onRevoke(miner)}
              >
                {miner.status === "revoked" ? "Revoked" : "Revoke"}
              </button>
            </article>
          ))}
        </div>
      </section>
    </div>
  );
}

function WalletView({
  wallet,
  walletStorageState,
  walletRecordAddress,
  password,
  setPassword,
  busy,
  message,
  qrData,
  recipient,
  setRecipient,
  amount,
  setAmount,
  fee,
  setFee,
  onCreate,
  onUnlock,
  onLock,
  onExport,
  onImport,
  onCopy,
  onSend,
  source,
  walletBalance,
}: {
  wallet: UnlockedWallet | null;
  walletStorageState: WalletStorageState;
  walletRecordAddress: string;
  password: string;
  setPassword: (value: string) => void;
  busy: boolean;
  message: string;
  qrData: string;
  recipient: string;
  setRecipient: (value: string) => void;
  amount: string;
  setAmount: (value: string) => void;
  fee: string;
  setFee: (value: string) => void;
  onCreate: (event: FormEvent) => void;
  onUnlock: (event: FormEvent) => void;
  onLock: () => void;
  onExport: () => void;
  onImport: (file: File | undefined) => void;
  onCopy: () => void;
  onSend: (event: FormEvent) => void;
  source: string;
  walletBalance: number | null;
}) {
  const address = wallet?.address ?? walletRecordAddress;
  const balanceLabel =
    source === "live" && walletBalance !== null
      ? walletBalance.toLocaleString("en", { maximumFractionDigits: 6 })
      : "—";
  return (
    <div className="page-frame">
      <PageHeading
        eyebrow="DEVICE-LOCAL TESTNET WALLET"
        title="Your keys stay"
        italic="with you."
        text="P-256 keys are encrypted with PBKDF2 + AES-GCM in IndexedDB. No mnemonic, custody service, cookie, or plaintext browser storage."
        aside={<span className={`lock-state ${wallet ? "open" : ""}`}>{wallet ? "UNLOCKED · 5 MIN AUTO-LOCK" : "ENCRYPTED · LOCKED"}</span>}
      />

      {message && <div className="wallet-message" role="status">{message}</div>}

      {walletStorageState === "loading" || walletStorageState === "error" ? (
        <section className="panel wallet-form" aria-live="polite">
          <PanelHead
            kicker="LOCAL STORAGE"
            title={
              walletStorageState === "loading"
                ? "Checking encrypted wallet"
                : "Wallet storage unavailable"
            }
            action="fail closed"
          />
          <p>
            {walletStorageState === "loading"
              ? "Creation and import remain disabled until the existing-wallet check completes."
              : "No wallet will be created or replaced while browser storage cannot be read. Reload after restoring IndexedDB access."}
          </p>
        </section>
      ) : walletStorageState === "absent" ? (
        <div className="wallet-onboarding">
          <section className="wallet-principles">
            <span className="eyebrow">NEW WALLET</span>
            <h2>One encrypted file.<br />No half-built seed phrase.</h2>
            <ol>
              <li><b>01</b><span>P-256 private key generated by Web Crypto.</span></li>
              <li><b>02</b><span>310,000-round PBKDF2 derives an AES-256 key.</span></li>
              <li><b>03</b><span>Only ciphertext and the public identity reach IndexedDB.</span></li>
            </ol>
          </section>
          <form className="wallet-form panel" onSubmit={onCreate}>
            <PanelHead kicker="CREATE" title="Protect this wallet" action="local only" />
            <label htmlFor="new-password">Encryption password</label>
            <input
              id="new-password"
              type="password"
              minLength={12}
              autoComplete="new-password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              placeholder="At least 12 characters"
              required
            />
            <p>This password cannot be recovered. Export the encrypted key file after creation.</p>
            <button className="primary-button wide" disabled={busy} type="submit">
              {busy ? "Encrypting…" : "Create encrypted wallet"}
            </button>
            <label className="file-button">
              Verify &amp; import encrypted key file
              <input
                type="file"
                accept="application/json,.json"
                disabled={busy}
                onChange={(event) => {
                  const file = event.target.files?.[0];
                  event.target.value = "";
                  void onImport(file);
                }}
              />
            </label>
          </form>
        </div>
      ) : !wallet ? (
        <div className="unlock-layout">
          <section className="address-card">
            <span className="eyebrow">ENCRYPTED WALLET FOUND</span>
            <h2>
              {address
                ? `${address.slice(0, 12)}…${address.slice(-10)}`
                : "Address verification required"}
            </h2>
            <p>
              Unlock this file to authenticate its public identity against the
              encrypted private key.
            </p>
            {source === "live" && address && (
              <p>Public finalized balance: <b>{balanceLabel} EPDN</b></p>
            )}
            <div className="wallet-actions">
              <button className="quiet-button" onClick={onExport}>Export encrypted file</button>
              <label className="file-button compact">
                Verify &amp; replace from file
                <input
                  type="file"
                  accept="application/json,.json"
                  disabled={busy}
                  onChange={(event) => {
                    const file = event.target.files?.[0];
                    event.target.value = "";
                    void onImport(file);
                  }}
                />
              </label>
            </div>
          </section>
          <form className="wallet-form panel" onSubmit={onUnlock}>
            <PanelHead kicker="UNLOCK" title="Decrypt in memory" action="auto-lock 5m" />
            <label htmlFor="unlock-password">Wallet password</label>
            <input
              id="unlock-password"
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              required
            />
            <button className="primary-button wide" disabled={busy} type="submit">
              {busy ? "Decrypting…" : "Unlock wallet"}
            </button>
          </form>
        </div>
      ) : (
        <div className="wallet-grid">
          <section className="balance-card">
            <div className="balance-head">
              <span>AVAILABLE TESTNET BALANCE</span>
              <button className="quiet-button compact" onClick={onLock}>Lock now</button>
            </div>
            <strong>{balanceLabel} <small>EPDN</small></strong>
            <p>Finalized chain balance · no monetary value</p>
            <div className="receive-block">
              {qrData && (
                <Image
                  src={qrData}
                  alt={`QR code for EPDN address ${address}`}
                  width={176}
                  height={176}
                  unoptimized
                />
              )}
              <div>
                <span className="eyebrow">RECEIVE ADDRESS</span>
                <code>{address}</code>
                <button className="quiet-button" onClick={onCopy}>Copy &amp; verify</button>
              </div>
            </div>
          </section>
          <form className="panel transfer-form" onSubmit={onSend}>
            <PanelHead kicker="TRANSFER" title="Sign on this device" action={source === "live" ? "broadcast ready" : "demo · no broadcast"} />
            <label htmlFor="recipient">Recipient</label>
            <input
              id="recipient"
              value={recipient}
              onChange={(event) => setRecipient(event.target.value.trim())}
              placeholder="64-character lowercase address"
              autoComplete="off"
              required
            />
            <div className="field-pair">
              <label>Amount<input type="number" min="1" step="1" value={amount} onChange={(event) => setAmount(event.target.value)} /></label>
              <label>Network fee<input type="number" min="0" step="1" value={fee} onChange={(event) => setFee(event.target.value)} /></label>
            </div>
            <div className="transaction-summary">
              <span>Total</span><b>{protocolUnitTotal(amount, fee)} EPDN</b>
            </div>
            <button className="primary-button wide" disabled={busy} type="submit">
              Review, sign &amp; broadcast
            </button>
            <p>Only public fields and the 64-byte ES256 signature are sent. The private key never enters the request.</p>
          </form>
        </div>
      )}
    </div>
  );
}

function Metric({
  label,
  value,
  unit,
  delta,
}: {
  label: string;
  value: string;
  unit?: string;
  delta: string;
}) {
  return (
    <article className="metric">
      <span>{label}</span>
      <strong>{value} {unit && <small>{unit}</small>}</strong>
      <p>{delta}</p>
    </article>
  );
}

function PanelHead({
  kicker,
  title,
  action,
}: {
  kicker: string;
  title: string;
  action: string;
}) {
  return (
    <header className="panel-head">
      <div><span>{kicker}</span><h2>{title}</h2></div>
      <small>{action}</small>
    </header>
  );
}

function PageHeading({
  eyebrow,
  title,
  italic,
  text,
  aside,
}: {
  eyebrow: string;
  title: string;
  italic: string;
  text: string;
  aside: React.ReactNode;
}) {
  return (
    <header className="page-heading">
      <div>
        <span className="eyebrow">{eyebrow}</span>
        <h1>{title} <em>{italic}</em></h1>
        <p>{text}</p>
      </div>
      {aside}
    </header>
  );
}
