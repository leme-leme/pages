import { type NextRequest } from "next/server";
import { and, eq, sql } from "drizzle-orm";
import { db } from "@/db";
import { projectAnalyticsConfigTable } from "@/db/schema";
import { generateSiteAnalyticsScript } from "@/lib/analytics/site-snippet";

// Public endpoint. The deployed site embeds:
//   <script src="https://<cms>/api/<owner>/<repo>/<branch>/analytics/snippet.js" async></script>
// and we serve a JS bundle that injects whatever providers the project owner
// configured.

const ALLOW_ORIGIN = "*";

const findRow = (owner: string, repo: string, branch: string) =>
  db.query.projectAnalyticsConfigTable.findFirst({
    where: and(
      sql`lower(${projectAnalyticsConfigTable.owner}) = ${owner.toLowerCase()}`,
      sql`lower(${projectAnalyticsConfigTable.repo}) = ${repo.toLowerCase()}`,
      eq(projectAnalyticsConfigTable.branch, branch),
    ),
  });

const noop = "/* pages-cms analytics: no providers configured */";

const baseHeaders = (cacheSeconds: number): HeadersInit => ({
  "Content-Type": "application/javascript; charset=utf-8",
  "Cache-Control": `public, max-age=${cacheSeconds}, s-maxage=${cacheSeconds}`,
  "Access-Control-Allow-Origin": ALLOW_ORIGIN,
  "X-Content-Type-Options": "nosniff",
});

export async function GET(
  _request: NextRequest,
  context: { params: Promise<{ owner: string; repo: string; branch: string }> },
) {
  const params = await context.params;
  const row = (await findRow(params.owner, params.repo, params.branch))
    ?? (await findRow(params.owner, params.repo, ""));

  if (!row || (!row.ga4MeasurementId && !row.plausibleDomain && !row.cfBeaconToken)) {
    return new Response(noop, { headers: baseHeaders(60) });
  }

  const script = generateSiteAnalyticsScript({
    ga4MeasurementId: row.ga4MeasurementId,
    plausibleDomain: row.plausibleDomain,
    plausibleApiHost: row.plausibleApiHost,
    cfBeaconToken: row.cfBeaconToken,
    requireConsent: !!row.requireConsent,
    honorDnt: !!row.honorDnt,
  });

  return new Response(script, { headers: baseHeaders(300) });
}

export async function OPTIONS() {
  return new Response(null, {
    status: 204,
    headers: {
      "Access-Control-Allow-Origin": ALLOW_ORIGIN,
      "Access-Control-Allow-Methods": "GET, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
      "Access-Control-Max-Age": "86400",
    },
  });
}
