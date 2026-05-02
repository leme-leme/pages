import { type NextRequest } from "next/server";
import { requireApiUserSession } from "@/lib/session-server";
import { requirePermission } from "@/lib/authz-server";
import {
  errorsByDay,
  eventsByDay,
  isAnalyticsQueryConfigured,
  storageBytesByDay,
  topActors,
  topCountries,
  topResources,
  userAgentBuckets,
  webVitalsByDay,
} from "@/lib/analytics/query";
import { deployStats, deploysByDay } from "@/lib/analytics/deploys";
import { toErrorResponse } from "@/lib/api-error";

const ALLOWED_INTERVALS = new Set(["1d", "7d", "30d", "90d"]);

const csvEscape = (value: unknown): string => {
  const s = value == null ? "" : String(value);
  if (/[",\n\r]/.test(s)) return `"${s.replace(/"/g, '""')}"`;
  return s;
};

const flattenForCsv = (data: Record<string, unknown[]>): string => {
  const rows: string[] = [];
  rows.push(["section", "key1", "key2", "key3", "value"].join(","));
  for (const [section, list] of Object.entries(data)) {
    for (const row of list) {
      const r = row as Record<string, unknown>;
      const keys = Object.keys(r);
      // pad to 3 keys + 1 value cell
      const k1 = keys[0] ? `${keys[0]}=${r[keys[0]]}` : "";
      const k2 = keys[1] ? `${keys[1]}=${r[keys[1]]}` : "";
      const k3 = keys[2] ? `${keys[2]}=${r[keys[2]]}` : "";
      const valKey = keys.find((k) => k === "count" || k === "value" || k === "bytes" || k === "p75") ?? keys[keys.length - 1];
      rows.push([section, k1, k2, k3, r[valKey]].map(csvEscape).join(","));
    }
  }
  return rows.join("\n");
};

export async function GET(
  request: NextRequest,
  context: { params: Promise<{ owner: string; repo: string; branch: string }> },
) {
  try {
    const params = await context.params;
    const sessionResult = await requireApiUserSession();
    if ("response" in sessionResult) return sessionResult.response;
    const user = sessionResult.user;

    await requirePermission(user, params.owner, params.repo, "admin", undefined, params.branch);

    const url = new URL(request.url);
    const intervalParam = url.searchParams.get("interval") ?? "7d";
    const interval = ALLOWED_INTERVALS.has(intervalParam)
      ? (intervalParam as "1d" | "7d" | "30d" | "90d")
      : "7d";
    const format = url.searchParams.get("format") ?? "json";

    if (!isAnalyticsQueryConfigured()) {
      const empty = {
        events: [], errors: [], storage: [], webVitals: [],
        topActors: [], topEntries: [], topMedia: [],
        topCountries: [], userAgents: [], unconfigured: true,
        deploys: { stats: null, byDay: [] },
      };
      return Response.json({ status: "success", data: empty });
    }

    const owner = params.owner;
    const repo = params.repo;
    // Deploy stats come from D1 (no AE dep); always fetch.
    const deployInterval = interval === "1d" ? "7d" : interval;
    const [
      events, errors, storage, webVitals,
      actors, entries, media, countries, userAgents,
      stats, byDay,
    ] = await Promise.all([
      eventsByDay(interval, { owner, repo }).catch(() => []),
      errorsByDay(interval, { owner, repo }).catch(() => []),
      storageBytesByDay(interval, { owner, repo }).catch(() => []),
      webVitalsByDay(interval, { owner, repo }).catch(() => []),
      topActors(interval, { owner, repo, limit: 10 }).catch(() => []),
      topResources("collection", interval, { owner, repo, limit: 10 }).catch(() => []),
      topResources("media", interval, { owner, repo, limit: 10 }).catch(() => []),
      topCountries(interval, { owner, repo, limit: 10 }).catch(() => []),
      userAgentBuckets(interval, { owner, repo }).catch(() => []),
      deployStats(deployInterval, { owner, repo }).catch(() => null),
      deploysByDay(deployInterval, { owner, repo }).catch(() => []),
    ]);

    const data = {
      events, errors, storage, webVitals,
      topActors: actors,
      topEntries: entries,
      topMedia: media,
      topCountries: countries,
      userAgents,
      deploys: { stats, byDay },
    };

    if (format === "csv") {
      const csv = flattenForCsv({
        events: data.events,
        errors: data.errors,
        storage: data.storage,
        webVitals: data.webVitals,
        topActors: data.topActors,
        topEntries: data.topEntries,
        topMedia: data.topMedia,
        topCountries: data.topCountries,
        userAgents: data.userAgents,
        deploysByDay: data.deploys.byDay,
      });
      return new Response(csv, {
        headers: {
          "Content-Type": "text/csv; charset=utf-8",
          "Content-Disposition": `attachment; filename="${owner}-${repo}-${interval}.csv"`,
        },
      });
    }

    return Response.json({ status: "success", data });
  } catch (error) {
    return toErrorResponse(error, { route: "/analytics/dashboard" });
  }
}
