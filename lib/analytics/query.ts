import { ColumnMappings } from "./schema";

const ACCOUNT_ID = process.env.CF_ACCOUNT_ID || "";
const API_TOKEN = process.env.CF_ANALYTICS_API_TOKEN || "";
const DATASET = process.env.AE_DATASET || "pages_cms_events";

const isConfigured = () => Boolean(ACCOUNT_ID && API_TOKEN);

type SqlRow = Record<string, string | number>;
type SqlResponse<T> = { meta: unknown; data: T[]; rows: number };

// Cloudflare Analytics Engine SQL API.
// Docs: https://developers.cloudflare.com/analytics/analytics-engine/sql-reference/
//
// AE SQL only supports SELECT. There is no parameter binding. Every value we
// interpolate must be sanitized to alphanumerics + a tiny punctuation set.
const safeIdent = (value: string) => value.replace(/[^A-Za-z0-9_:.\-/]/g, "");
const safeSqlString = (value: string) => value.replace(/[^A-Za-z0-9_:.\- /@]/g, "");

async function aeQuery<T extends SqlRow>(sql: string): Promise<SqlResponse<T>> {
  if (!isConfigured()) {
    throw new Error("Cloudflare Analytics Engine query API is not configured.");
  }
  const url = `https://api.cloudflare.com/client/v4/accounts/${ACCOUNT_ID}/analytics_engine/sql`;
  const res = await fetch(url, {
    method: "POST",
    headers: {
      "content-type": "text/plain",
      Authorization: `Bearer ${API_TOKEN}`,
    },
    body: sql,
  });
  if (!res.ok) {
    const body = await res.text();
    throw new Error(`AE SQL query failed (${res.status}): ${body}`);
  }
  return (await res.json()) as SqlResponse<T>;
}

const intervalSql = (interval: "1d" | "7d" | "30d" | "90d") =>
  `timestamp > NOW() - INTERVAL '${interval.replace("d", "")}' DAY`;

const repoFilterSql = (owner?: string | null, repo?: string | null) => {
  const parts: string[] = [];
  if (owner) parts.push(`${ColumnMappings.owner} = '${safeSqlString(owner.toLowerCase())}'`);
  if (repo) parts.push(`${ColumnMappings.repo} = '${safeSqlString(repo.toLowerCase())}'`);
  return parts.length > 0 ? `AND ${parts.join(" AND ")}` : "";
};

export type EventCount = { date: string; type: string; count: number };

export async function eventsByDay(
  interval: "1d" | "7d" | "30d" | "90d" = "30d",
  opts?: { owner?: string; repo?: string },
): Promise<EventCount[]> {
  const sql = `
    SELECT
      formatDateTime(toStartOfDay(timestamp), '%F') AS date,
      ${ColumnMappings.eventType} AS type,
      SUM(${ColumnMappings.count}) AS count
    FROM ${safeIdent(DATASET)}
    WHERE ${intervalSql(interval)}
      ${repoFilterSql(opts?.owner, opts?.repo)}
    GROUP BY date, type
    ORDER BY date ASC
    FORMAT JSON
  `;
  const res = await aeQuery<EventCount>(sql);
  return res.data;
}

export type ActorCount = { actorEmail: string; events: number };

export async function topActors(
  interval: "1d" | "7d" | "30d" | "90d" = "30d",
  opts?: { owner?: string; repo?: string; limit?: number },
): Promise<ActorCount[]> {
  const limit = Math.min(opts?.limit ?? 20, 100);
  const sql = `
    SELECT
      ${ColumnMappings.actorEmail} AS actorEmail,
      SUM(${ColumnMappings.count}) AS events
    FROM ${safeIdent(DATASET)}
    WHERE ${intervalSql(interval)}
      AND ${ColumnMappings.actorEmail} != ''
      ${repoFilterSql(opts?.owner, opts?.repo)}
    GROUP BY actorEmail
    ORDER BY events DESC
    LIMIT ${limit}
    FORMAT JSON
  `;
  const res = await aeQuery<ActorCount>(sql);
  return res.data;
}

export type ErrorCount = { date: string; status: string; route: string; count: number };

export async function errorsByDay(
  interval: "1d" | "7d" | "30d" | "90d" = "30d",
  opts?: { owner?: string; repo?: string },
): Promise<ErrorCount[]> {
  const sql = `
    SELECT
      formatDateTime(toStartOfDay(timestamp), '%F') AS date,
      ${ColumnMappings.status} AS status,
      ${ColumnMappings.route} AS route,
      SUM(${ColumnMappings.count}) AS count
    FROM ${safeIdent(DATASET)}
    WHERE ${intervalSql(interval)}
      AND index1 = 'cms.error'
      ${repoFilterSql(opts?.owner, opts?.repo)}
    GROUP BY date, status, route
    ORDER BY date ASC, count DESC
    FORMAT JSON
  `;
  const res = await aeQuery<ErrorCount>(sql);
  return res.data;
}

export type WebVitalQuantile = { metric: string; date: string; p75: number; p99: number; samples: number };

export async function webVitalsByDay(
  interval: "1d" | "7d" | "30d" | "90d" = "30d",
  opts?: { owner?: string; repo?: string },
): Promise<WebVitalQuantile[]> {
  const sql = `
    SELECT
      ${ColumnMappings.metric} AS metric,
      formatDateTime(toStartOfDay(timestamp), '%F') AS date,
      quantileWeighted(0.75, ${ColumnMappings.numericValue}, _sample_interval) AS p75,
      quantileWeighted(0.99, ${ColumnMappings.numericValue}, _sample_interval) AS p99,
      SUM(_sample_interval) AS samples
    FROM ${safeIdent(DATASET)}
    WHERE ${intervalSql(interval)}
      AND index1 = 'cms.web-vital'
      ${repoFilterSql(opts?.owner, opts?.repo)}
    GROUP BY metric, date
    ORDER BY date ASC, metric
    FORMAT JSON
  `;
  const res = await aeQuery<WebVitalQuantile>(sql);
  return res.data;
}

export type StorageBytesByDay = { date: string; bytesIn: number; bytesOut: number };

export async function storageBytesByDay(
  interval: "1d" | "7d" | "30d" | "90d" = "30d",
  opts?: { owner?: string; repo?: string },
): Promise<StorageBytesByDay[]> {
  const sql = `
    SELECT
      formatDateTime(toStartOfDay(timestamp), '%F') AS date,
      sumIf(${ColumnMappings.bytes}, index1 = 'cms.media.upload') AS bytesIn,
      sumIf(${ColumnMappings.bytes}, index1 = 'cms.media.egress') AS bytesOut
    FROM ${safeIdent(DATASET)}
    WHERE ${intervalSql(interval)}
      ${repoFilterSql(opts?.owner, opts?.repo)}
    GROUP BY date
    ORDER BY date ASC
    FORMAT JSON
  `;
  const res = await aeQuery<StorageBytesByDay>(sql);
  return res.data;
}

export { isConfigured as isAnalyticsQueryConfigured };
