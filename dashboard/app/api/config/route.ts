export const dynamic = "force-dynamic";

export async function GET() {
  const candidate =
    process.env.EPDN_API_BASE_URL ??
    process.env.NEXT_PUBLIC_EPDN_API_BASE_URL ??
    "";
  let apiBaseUrl = "";
  try {
    const url = new URL(candidate);
    if (url.protocol === "https:" || url.protocol === "http:") {
      apiBaseUrl = url.toString().replace(/\/$/, "");
    }
  } catch {
    apiBaseUrl = "";
  }

  return Response.json(
    {
      apiBaseUrl,
      chainId: process.env.EPDN_CHAIN_ID ?? "epdn-local-testnet-v1",
      eventsPath: "/api/v1/events",
    },
    { headers: { "Cache-Control": "no-store" } },
  );
}
