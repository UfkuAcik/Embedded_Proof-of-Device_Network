import { getChatGPTUser } from "../../../chatgpt-auth";
import { normalizeRevocationReason } from "../../../lib/revocation.mjs";

export const dynamic = "force-dynamic";

export async function POST(request: Request) {
  const isAuthenticated = (await getChatGPTUser()) !== null;
  if (!isAuthenticated) {
    return Response.json(
      { error: "Sign in is required for device write actions." },
      { status: 401 },
    );
  }

  const origin = request.headers.get("origin");
  if (origin && origin !== new URL(request.url).origin) {
    return Response.json(
      { error: "Cross-origin write rejected." },
      { status: 403 },
    );
  }

  const body = (await request.json().catch(() => null)) as
    | { publicId?: unknown; reason?: unknown }
    | null;
  const publicId = typeof body?.publicId === "string" ? body.publicId : "";
  const reason = normalizeRevocationReason(body?.reason);
  if (!/^[0-9a-f]{64}$/.test(publicId) || !reason) {
    return Response.json(
      { error: "Invalid device ID or revocation reason." },
      { status: 400 },
    );
  }

  const configuredBaseUrl = process.env.EPDN_API_BASE_URL;
  let baseUrl: URL;
  try {
    baseUrl = new URL(configuredBaseUrl ?? "");
    if (
      (baseUrl.protocol !== "http:" && baseUrl.protocol !== "https:") ||
      baseUrl.username ||
      baseUrl.password ||
      baseUrl.pathname !== "/" ||
      baseUrl.search ||
      baseUrl.hash
    ) {
      throw new Error("validator origin must be an HTTP(S) origin");
    }
  } catch {
    return Response.json(
      { error: "No validator API is configured; demo data was not changed." },
      { status: 503 },
    );
  }

  const headers = new Headers({ "content-type": "application/json" });
  const adminToken = process.env.EPDN_ADMIN_API_TOKEN;
  if (adminToken) headers.set("x-epdn-admin-token", adminToken);

  // The authority is trusted server-only configuration, while publicId has
  // already passed a fixed 32-byte lowercase-hex allowlist. Request data
  // therefore cannot change the destination scheme, host, port, or path shape.
  const endpoint = new URL(
    `/api/v1/miners/${publicId}/commands`,
    baseUrl.origin,
  );
  const response = await fetch(
    endpoint,
    {
      method: "POST",
      headers,
      body: JSON.stringify({ command: "revoke", reason }),
      redirect: "error",
    },
  );
  const result = await response.text();
  return new Response(result, {
    status: response.status,
    headers: {
      "content-type":
        response.headers.get("content-type") ?? "application/json",
      "cache-control": "no-store",
    },
  });
}
