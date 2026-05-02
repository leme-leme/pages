import { type NextRequest } from "next/server";
import { z } from "zod";
import { writeEvent } from "@/lib/analytics/collect";
import { enforce as enforceRateLimit } from "@/lib/rate-limit";
import { db } from "@/db";
import { projectAnalyticsConfigTable } from "@/db/schema";
import { and, eq, sql } from "drizzle-orm";

// Public endpoint. The deployed site can record custom events without auth:
//
//   navigator.sendBeacon(
//     "https://<cms>/api/<owner>/<repo>/<branch>/analytics/event",
//     JSON.stringify({ name: "newsletter.signup", value: 1, page: location.pathname })
//   );
//
// Stored in the same AE dataset under index `site.<name>` so it joins with
// CMS events in the dashboard. Requires the project to have an analytics
// config row (otherwise we'd accept events for any random project).

const bodySchema = z.object({
  name: z.string().regex(/^[a-z0-9._-]{1,48}$/i, "name must be 1-48 chars [a-z0-9._-]"),
  value: z.number().finite().optional(),
  page: z.string().max(2048).optional(),
  referrer: z.string().max(2048).optional(),
  metadata: z.record(z.string().max(64), z.string().max(256)).optional(),
});

const ALLOW_ORIGIN = "*";

const corsHeaders = (): HeadersInit => ({
  "Access-Control-Allow-Origin": ALLOW_ORIGIN,
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
  "Access-Control-Max-Age": "86400",
});

const isPrivacyOptOut = (request: Request) => {
  const dnt = request.headers.get("dnt") || request.headers.get("DNT");
  const gpc = request.headers.get("sec-gpc");
  return dnt === "1" || gpc === "1";
};

export async function OPTIONS() {
  return new Response(null, { status: 204, headers: corsHeaders() });
}

export async function POST(
  request: NextRequest,
  context: { params: Promise<{ owner: string; repo: string; branch: string }> },
) {
  const params = await context.params;

  // Project must opt in by having a config row (any provider configured or empty row).
  const cfg = await db.query.projectAnalyticsConfigTable.findFirst({
    where: and(
      sql`lower(${projectAnalyticsConfigTable.owner}) = ${params.owner.toLowerCase()}`,
      sql`lower(${projectAnalyticsConfigTable.repo}) = ${params.repo.toLowerCase()}`,
      eq(projectAnalyticsConfigTable.branch, params.branch),
    ),
  }) ?? await db.query.projectAnalyticsConfigTable.findFirst({
    where: and(
      sql`lower(${projectAnalyticsConfigTable.owner}) = ${params.owner.toLowerCase()}`,
      sql`lower(${projectAnalyticsConfigTable.repo}) = ${params.repo.toLowerCase()}`,
      eq(projectAnalyticsConfigTable.branch, ""),
    ),
  });

  if (!cfg) {
    return new Response("project not configured for analytics", { status: 404, headers: corsHeaders() });
  }
  if (cfg.honorDnt && isPrivacyOptOut(request)) {
    return new Response(null, { status: 204, headers: corsHeaders() });
  }

  const body = await request.json().catch(() => null);
  const parsed = bodySchema.safeParse(body);
  if (!parsed.success) {
    return new Response(`Invalid: ${parsed.error.message}`, { status: 400, headers: corsHeaders() });
  }

  // Rate-limit per (project, source IP) bucket so a hostile site can't blow
  // through our AE quota. CF-Connecting-IP is set on the worker.
  const ip = request.headers.get("cf-connecting-ip") ?? "unknown";
  const bucket = `${params.owner}/${params.repo}:${ip}`;
  try {
    await enforceRateLimit(bucket, "presign", 1); // reuse the 120/min bucket
  } catch {
    return new Response("rate-limited", { status: 429, headers: corsHeaders() });
  }

  const ua = request.headers.get("user-agent") ?? undefined;
  const country = request.headers.get("cf-ipcountry") ?? undefined;

  writeEvent({
    type: `site.${parsed.data.name}` as any, // not in EventType union, but AE accepts any string
    owner: params.owner,
    repo: params.repo,
    branch: params.branch,
    actor: { type: "system" },
    resourceType: "site-event",
    resourceId: parsed.data.name,
    route: parsed.data.page,
    userAgent: ua,
    country,
    numericValue: parsed.data.value,
    extra: parsed.data.metadata,
  });

  return new Response(null, { status: 204, headers: corsHeaders() });
}
