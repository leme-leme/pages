import { db } from "@/db";
import { analyticsRollupTable } from "@/db/schema";
import { and, eq } from "drizzle-orm";
import { ColumnMappings } from "./schema";
import { isAnalyticsQueryConfigured } from "./query";

const ACCOUNT_ID = process.env.CF_ACCOUNT_ID || "";
const API_TOKEN = process.env.CF_ANALYTICS_API_TOKEN || "";
const DATASET = process.env.AE_DATASET || "pages_cms_events";

const safeIdent = (value: string) => value.replace(/[^A-Za-z0-9_:.\-/]/g, "");

type RollupRow = {
  date: string;
  owner: string;
  repo: string;
  type: string;
  count: number;
  bytes: number;
  uniqueActors: number;
};

async function aeQuery<T>(sql: string): Promise<{ data: T[] }> {
  const url = `https://api.cloudflare.com/client/v4/accounts/${ACCOUNT_ID}/analytics_engine/sql`;
  const res = await fetch(url, {
    method: "POST",
    headers: {
      "content-type": "text/plain",
      Authorization: `Bearer ${API_TOKEN}`,
    },
    body: sql,
  });
  if (!res.ok) throw new Error(`AE SQL ${res.status}: ${await res.text()}`);
  return (await res.json()) as { data: T[] };
}

// Aggregates yesterday into analytics_rollup. Idempotent — INSERT OR REPLACE
// on the (date, owner, repo, eventType) unique index.
export async function rollupYesterday(): Promise<{ rows: number }> {
  if (!isAnalyticsQueryConfigured()) return { rows: 0 };

  const sql = `
    SELECT
      formatDateTime(toStartOfDay(timestamp), '%F') AS date,
      ${ColumnMappings.owner} AS owner,
      ${ColumnMappings.repo} AS repo,
      ${ColumnMappings.eventType} AS type,
      SUM(${ColumnMappings.count}) AS count,
      SUM(${ColumnMappings.bytes}) AS bytes,
      uniq(${ColumnMappings.actorEmail}) AS uniqueActors
    FROM ${safeIdent(DATASET)}
    WHERE timestamp > toStartOfDay(NOW() - INTERVAL '1' DAY)
      AND timestamp < toStartOfDay(NOW())
    GROUP BY date, owner, repo, type
    FORMAT JSON
  `;

  const result = await aeQuery<RollupRow>(sql);
  let written = 0;

  for (const row of result.data) {
    const existing = await db.query.analyticsRollupTable.findFirst({
      where: and(
        eq(analyticsRollupTable.date, row.date),
        eq(analyticsRollupTable.owner, row.owner ?? ""),
        eq(analyticsRollupTable.repo, row.repo ?? ""),
        eq(analyticsRollupTable.eventType, row.type ?? ""),
      ),
    });
    if (existing) {
      await db.update(analyticsRollupTable)
        .set({
          count: Number(row.count) || 0,
          bytes: Number(row.bytes) || 0,
          uniqueActors: Number(row.uniqueActors) || 0,
        })
        .where(eq(analyticsRollupTable.id, existing.id));
    } else {
      await db.insert(analyticsRollupTable).values({
        date: row.date,
        owner: row.owner ?? "",
        repo: row.repo ?? "",
        eventType: row.type ?? "",
        count: Number(row.count) || 0,
        bytes: Number(row.bytes) || 0,
        uniqueActors: Number(row.uniqueActors) || 0,
      });
    }
    written += 1;
  }

  return { rows: written };
}

// Suppress unused
void ACCOUNT_ID;
void API_TOKEN;
