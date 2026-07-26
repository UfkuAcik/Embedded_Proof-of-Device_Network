export const MAX_REVOCATION_REASON_BYTES = 128;

export function normalizeRevocationReason(value) {
  if (typeof value !== "string") return null;
  const reason = value.trim();
  if (
    reason.length < 4 ||
    new TextEncoder().encode(reason).length > MAX_REVOCATION_REASON_BYTES
  ) {
    return null;
  }
  return reason;
}
