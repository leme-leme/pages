import { db } from "@/db";
import { actionRunTable } from "@/db/schema";
import { and, gt, sql } from "drizzle-orm";

export type DeployStats = {
  total: number;
  succeeded: number;
  failed: number;
  inProgress: number;
  successRate: number;          // 0..1, of completed runs only
  meanDurationMs: number | null;
  p95DurationMs: number | null;
};

export type DeployBucket = {
  date: string;
  total: number;
  succeeded: number;
  failed: number;
};

const intervalToDays = (interval: "7d" | "30d" | "90d") => parseInt(interval, 10);

const sinceFilter = (interval: "7d" | "30d" | "90d") => {
  const days = intervalToDays(interval);
  const since = new Date(Date.now() - days * 24 * 60 * 60 * 1000);
  return gt(actionRunTable.createdAt, since);
};

const repoFilter = (owner?: string, repo?: string) => {
  const parts: any[] = [];
  if (owner) parts.push(sql`lower(${actionRunTable.owner}) = lower(${owner})`);
  if (repo) parts.push(sql`lower(${actionRunTable.repo}) = lower(${repo})`);
  return parts;
};

// Aggregate stats: success rate, mean / p95 duration, totals.
// Computed in JS (D1 has no quantile fn) — bound to N=10000 max rows.
export async function deployStats(
  interval: "7d" | "30d" | "90d" = "30d",
  opts?: { owner?: string; repo?: string },
): Promise<DeployStats> {
  const rows = await db.query.actionRunTable.findMany({
    where: and(sinceFilter(interval), ...repoFilter(opts?.owner, opts?.repo)),
    columns: {
      status: true,
      conclusion: true,
      createdAt: true,
      completedAt: true,
    },
    limit: 10_000,
  });

  let succeeded = 0;
  let failed = 0;
  let inProgress = 0;
  const durations: number[] = [];
  for (const row of rows) {
    if (row.status !== "completed") {
      inProgress += 1;
      continue;
    }
    if (row.conclusion === "success") succeeded += 1;
    else if (row.conclusion === "failure" || row.conclusion === "cancelled" || row.conclusion === "timed_out") failed += 1;
    if (row.completedAt && row.createdAt) {
      durations.push(row.completedAt.getTime() - row.createdAt.getTime());
    }
  }

  durations.sort((a, b) => a - b);
  const completed = succeeded + failed;
  const mean = durations.length > 0 ? durations.reduce((s, d) => s + d, 0) / durations.length : null;
  const p95Idx = durations.length > 0 ? Math.floor(durations.length * 0.95) : -1;
  const p95 = p95Idx >= 0 && p95Idx < durations.length ? durations[p95Idx] : null;

  return {
    total: rows.length,
    succeeded,
    failed,
    inProgress,
    successRate: completed > 0 ? succeeded / completed : 0,
    meanDurationMs: mean,
    p95DurationMs: p95,
  };
}

// Per-day totals for a stacked bar (succeeded vs failed).
export async function deploysByDay(
  interval: "7d" | "30d" | "90d" = "30d",
  opts?: { owner?: string; repo?: string },
): Promise<DeployBucket[]> {
  const rows = await db.query.actionRunTable.findMany({
    where: and(sinceFilter(interval), ...repoFilter(opts?.owner, opts?.repo)),
    columns: {
      conclusion: true,
      createdAt: true,
    },
    limit: 10_000,
  });

  const map = new Map<string, DeployBucket>();
  for (const row of rows) {
    const date = row.createdAt.toISOString().slice(0, 10);
    let bucket = map.get(date);
    if (!bucket) {
      bucket = { date, total: 0, succeeded: 0, failed: 0 };
      map.set(date, bucket);
    }
    bucket.total += 1;
    if (row.conclusion === "success") bucket.succeeded += 1;
    else if (row.conclusion === "failure" || row.conclusion === "cancelled" || row.conclusion === "timed_out") bucket.failed += 1;
  }

  return Array.from(map.values()).sort((a, b) => a.date.localeCompare(b.date));
}
