import { db } from "@/db";
import { cacheFileTable } from "@/db/schema";
import { and, eq, isNull, lt, or } from "drizzle-orm";
import { getStorageConfig, s3Delete, s3List } from "@/lib/storage/s3";
import { recordUsage } from "@/lib/storage/usage";
import { recordAuditEvent } from "@/lib/audit";

const ORPHAN_AGE_DAYS = parseInt(process.env.STORAGE_ORPHAN_AGE_DAYS ?? "30", 10);

// §1.4: delete S3 objects + DB rows for media that hasn't been referenced
// (i.e. served via /api/s3) for `STORAGE_ORPHAN_AGE_DAYS` days.
export async function gcOrphanMedia(opts?: { dryRun?: boolean; max?: number }) {
  const cutoff = new Date(Date.now() - ORPHAN_AGE_DAYS * 24 * 60 * 60 * 1000);
  const max = opts?.max ?? 500;

  const orphans = await db.query.cacheFileTable.findMany({
    where: and(
      eq(cacheFileTable.provider, "s3"),
      or(isNull(cacheFileTable.referencedAt), lt(cacheFileTable.referencedAt, cutoff)),
      lt(cacheFileTable.updatedAt, cutoff),
    ),
    limit: max,
  });

  const deleted: { owner: string; repo: string; branch: string; key: string; size: number }[] = [];

  for (const row of orphans) {
    if (!row.s3Key) continue;
    if (opts?.dryRun) {
      deleted.push({
        owner: row.owner, repo: row.repo, branch: row.branch,
        key: row.s3Key, size: row.size ?? 0,
      });
      continue;
    }
    try {
      const cfg = await getStorageConfig(row.owner, row.repo, row.branch);
      if (!cfg) continue;
      await s3Delete(cfg, row.s3Key);
      await db.delete(cacheFileTable).where(eq(cacheFileTable.id, row.id));
      await recordUsage(row.owner, row.repo, row.branch, {
        bytesStoredDelta: -(row.size ?? 0),
        fileCountDelta: -1,
      });
      deleted.push({
        owner: row.owner, repo: row.repo, branch: row.branch,
        key: row.s3Key, size: row.size ?? 0,
      });
    } catch (error) {
      console.warn(`[lifecycle] failed to GC ${row.s3Key}`, error);
    }
  }

  if (deleted.length > 0) {
    await recordAuditEvent({
      actor: { type: "system", userId: null, email: null },
      action: "storage.gc.orphan",
      resourceType: "media",
      after: { count: deleted.length, totalBytes: deleted.reduce((s, d) => s + d.size, 0) },
    });
  }

  return { deleted };
}

// §1.5: walk S3 keys we know about (from cache_file) and verify they still
// exist; orphan rows whose object is missing → drop the cache row. Walk a
// distinct (owner, repo, branch) bucket per call so we don't blow the
// 30s scheduled-event budget.
export async function reconcileBucketWithCache(
  owner: string,
  repo: string,
  branch: string,
) {
  const cfg = await getStorageConfig(owner, repo, branch);
  if (!cfg) return { checked: 0, fixed: 0 };

  const lowerOwner = owner.toLowerCase();
  const lowerRepo = repo.toLowerCase();

  const rows = await db.query.cacheFileTable.findMany({
    where: and(
      eq(cacheFileTable.owner, lowerOwner),
      eq(cacheFileTable.repo, lowerRepo),
      eq(cacheFileTable.branch, branch),
      eq(cacheFileTable.provider, "s3"),
    ),
    limit: 5000,
  });

  if (rows.length === 0) return { checked: 0, fixed: 0 };

  const prefix = `${cfg.prefix ? cfg.prefix.replace(/\/+$/, "") + "/" : ""}${owner}/${repo}/${branch}/`;
  const liveKeys = new Set<string>();
  let next: string | undefined;
  do {
    const page = await s3List(cfg, prefix, next);
    page.keys.forEach((k) => liveKeys.add(k.key));
    next = page.next;
  } while (next);

  let fixed = 0;
  for (const row of rows) {
    if (!row.s3Key) continue;
    if (!liveKeys.has(row.s3Key)) {
      await db.delete(cacheFileTable).where(eq(cacheFileTable.id, row.id));
      await recordUsage(owner, repo, branch, {
        bytesStoredDelta: -(row.size ?? 0),
        fileCountDelta: -1,
      });
      fixed += 1;
    }
  }

  if (fixed > 0) {
    await recordAuditEvent({
      actor: { type: "system" },
      action: "storage.reconcile",
      resourceType: "media",
      owner, repo, branch,
      after: { fixed, checked: rows.length },
    });
  }

  return { checked: rows.length, fixed };
}

// Pick distinct (owner, repo, branch) tuples that have S3 rows, oldest reconcile first.
export async function pickReconcileTargets(limit = 5) {
  const rows = await db.query.cacheFileTable.findMany({
    where: eq(cacheFileTable.provider, "s3"),
    columns: { owner: true, repo: true, branch: true },
    limit: 10_000,
  });
  const seen = new Set<string>();
  const targets: { owner: string; repo: string; branch: string }[] = [];
  for (const row of rows) {
    const k = `${row.owner}/${row.repo}/${row.branch}`;
    if (seen.has(k)) continue;
    seen.add(k);
    targets.push({ owner: row.owner, repo: row.repo, branch: row.branch });
    if (targets.length >= limit) break;
  }
  return targets;
}
