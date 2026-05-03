import { type NextRequest } from "next/server";
import { generateSiteAnalyticsScript } from "@/lib/analytics/site-snippet";
import { resolveAnalyticsConfig } from "@/lib/analytics/resolve-config";

// Public endpoint. The deployed site embeds:
//   <script src="https://<cms>/api/<owner>/<repo>/<branch>/analytics/snippet.js" async></script>
// and we serve a JS bundle that injects whatever providers the project owner
// configured.

const ALLOW_ORIGIN = "*";

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
  const cfg = await resolveAnalyticsConfig(params.owner, params.repo, params.branch);

  if (!cfg) return new Response(noop, { headers: baseHeaders(60) });

  const script = generateSiteAnalyticsScript({
    ga4MeasurementId: cfg.ga4MeasurementId,
    cfBeaconToken: cfg.cfBeaconToken,
    requireConsent: cfg.requireConsent,
    honorDnt: cfg.honorDnt,
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
