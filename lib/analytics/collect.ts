import type { AnalyticsEvent } from "./schema";

const DISABLED = process.env.ANALYTICS_DISABLED === "true";
const MAX_BLOB_BYTES = 5120; // CF AE total blob byte cap; we stay well under.
const MAX_FIELD_BYTES = 256;

const trunc = (value: unknown): string => {
  if (value == null) return "";
  const s = typeof value === "string" ? value : String(value);
  if (s.length <= MAX_FIELD_BYTES) return s;
  return s.slice(0, MAX_FIELD_BYTES);
};

const stringifyExtra = (extra: Record<string, unknown> | null | undefined): string => {
  if (!extra) return "";
  try {
    const json = JSON.stringify(extra);
    return json.length <= MAX_FIELD_BYTES ? json : json.slice(0, MAX_FIELD_BYTES);
  } catch {
    return "";
  }
};

async function getAEBinding(): Promise<AnalyticsEngineDataset | null> {
  if (DISABLED) return null;
  if (typeof globalThis === "undefined" || typeof (globalThis as any).Cloudflare === "undefined") {
    // Not in a Worker runtime (e.g. client bundle that touched this file
    // through a shared import). Skip silently.
    try {
      const mod = await import("cloudflare:workers");
      const e = mod.env as unknown as { AE?: AnalyticsEngineDataset };
      return e.AE ?? null;
    } catch {
      return null;
    }
  }
  const mod = await import("cloudflare:workers");
  const e = mod.env as unknown as { AE?: AnalyticsEngineDataset };
  return e.AE ?? null;
}

export function writeEvent(event: AnalyticsEvent): void {
  void writeEventAsync(event);
}

async function writeEventAsync(event: AnalyticsEvent): Promise<void> {
  const ae = await getAEBinding();
  if (!ae) return;

  const blobs = [
    trunc(event.type),
    trunc(event.owner),
    trunc(event.repo),
    trunc(event.branch),
    trunc(event.actor?.type ?? "user"),
    trunc(event.actor?.userId),
    trunc(event.actor?.email),
    trunc(event.resourceType),
    trunc(event.resourceId),
    trunc(event.status),
    trunc(event.route),
    trunc(event.metric),
    trunc(event.navigationType),
    trunc(event.userAgent),
    trunc(event.country),
    trunc(event.errorMessage),
    stringifyExtra(event.extra),
  ];

  // sanity check: if we somehow blew the byte budget, drop trailing fields.
  let total = blobs.reduce((s, b) => s + b.length, 0);
  while (total > MAX_BLOB_BYTES && blobs.length > 1) {
    const dropped = blobs.pop()!;
    total -= dropped.length;
  }

  try {
    ae.writeDataPoint({
      indexes: [event.type],
      blobs,
      doubles: [
        1, // count — always 1 so SUM(double1) = events
        event.bytes ?? 0,
        event.durationMs ?? 0,
        event.numericValue ?? 0,
      ],
    });
  } catch (error) {
    // never let analytics break a request
    console.warn("[analytics] writeDataPoint failed", error);
  }
}
