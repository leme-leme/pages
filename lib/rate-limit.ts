import { db } from "@/db";
import { rateLimitTable } from "@/db/schema";
import { eq } from "drizzle-orm";
import { createHttpError } from "@/lib/api-error";

type LimitConfig = {
  capacity: number;
  refillPerSecond: number;
};

const limitDefaults: Record<string, LimitConfig> = {
  "upload": { capacity: 60, refillPerSecond: 60 / 60 }, // 60/min
  "upload-bytes": { capacity: 1_000_000_000, refillPerSecond: 1_000_000_000 / 3600 }, // 1GB/hr
  "presign": { capacity: 120, refillPerSecond: 120 / 60 }, // 120/min
  "delete": { capacity: 60, refillPerSecond: 60 / 60 },
};

export type LimitName = keyof typeof limitDefaults | (string & {});

export async function consume(
  bucketKey: string,
  limit: LimitName,
  amount = 1,
  override?: LimitConfig,
): Promise<{ allowed: boolean; remaining: number; retryAfter?: number }> {
  const cfg = override ?? limitDefaults[limit] ?? { capacity: 30, refillPerSecond: 0.5 };
  const now = Date.now();

  const row = await db.query.rateLimitTable.findFirst({
    where: eq(rateLimitTable.bucket, `${limit}:${bucketKey}`),
  });

  let tokens = row?.tokens ?? cfg.capacity;
  const last = row?.refilledAt?.getTime() ?? now;
  const elapsed = Math.max(0, now - last) / 1000;
  tokens = Math.min(cfg.capacity, tokens + Math.floor(elapsed * cfg.refillPerSecond));

  if (tokens < amount) {
    const deficit = amount - tokens;
    const retryAfter = Math.max(1, Math.ceil(deficit / cfg.refillPerSecond));
    await persist(`${limit}:${bucketKey}`, tokens, now);
    return { allowed: false, remaining: tokens, retryAfter };
  }

  tokens -= amount;
  await persist(`${limit}:${bucketKey}`, tokens, now);
  return { allowed: true, remaining: tokens };
}

const persist = async (bucket: string, tokens: number, ts: number) => {
  await db.insert(rateLimitTable)
    .values({ bucket, tokens, refilledAt: new Date(ts) })
    .onConflictDoUpdate({
      target: rateLimitTable.bucket,
      set: { tokens, refilledAt: new Date(ts) },
    });
};

export async function enforce(
  bucketKey: string,
  limit: LimitName,
  amount = 1,
) {
  const result = await consume(bucketKey, limit, amount);
  if (!result.allowed) {
    const err = createHttpError(
      `Rate limit exceeded. Retry in ${result.retryAfter}s.`,
      429,
    );
    (err as any).retryAfter = result.retryAfter;
    throw err;
  }
  return result;
}
