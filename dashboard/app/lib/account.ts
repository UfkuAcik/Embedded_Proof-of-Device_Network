export type WalletAccountState = {
  address: string;
  balance: number;
  nextNonce: bigint;
};

function nonNegativeSafeInteger(value: unknown, field: string): number {
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    value < 0
  ) {
    throw new Error(`Validator returned an invalid ${field}.`);
  }
  return value;
}

export function parseWalletAccountState(
  value: unknown,
  expectedAddress: string,
): WalletAccountState {
  if (!value || typeof value !== "object") {
    throw new Error("Validator returned an invalid account response.");
  }
  const account = value as Record<string, unknown>;
  if (
    typeof account.address !== "string" ||
    account.address !== expectedAddress
  ) {
    throw new Error("Validator returned an account for another address.");
  }
  return {
    address: account.address,
    balance: nonNegativeSafeInteger(account.balance, "account balance"),
    nextNonce: BigInt(
      nonNegativeSafeInteger(account.next_nonce, "account nonce"),
    ),
  };
}

export async function fetchWalletAccountState(
  baseUrl: string,
  address: string,
  fetcher: typeof fetch = fetch,
  signal?: AbortSignal,
): Promise<WalletAccountState> {
  if (!/^[0-9a-f]{64}$/.test(address)) {
    throw new Error("Wallet address is invalid.");
  }
  const response = await fetcher(
    `${baseUrl.replace(/\/$/, "")}/api/v1/address/${encodeURIComponent(address)}`,
    { signal, cache: "no-store" },
  );
  if (!response.ok) {
    throw new Error(`Account lookup failed with HTTP ${response.status}.`);
  }
  return parseWalletAccountState(await response.json(), address);
}
