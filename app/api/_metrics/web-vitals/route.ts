import { type NextRequest } from "next/server";
import { z } from "zod";
import { writeEvent } from "@/lib/analytics/collect";

const bodySchema = z.object({
  name: z.enum(["LCP", "INP", "CLS", "FCP", "TTFB"]),
  value: z.number().finite(),
  id: z.string().min(1).max(64),
  navigationType: z.string().max(32).optional(),
  page: z.string().max(2048).optional(),
  owner: z.string().max(64).optional(),
  repo: z.string().max(64).optional(),
  branch: z.string().max(64).optional(),
});

// Honor Do-Not-Track and the Sec-GPC (Global Privacy Control) header.
const isPrivacyOptOut = (request: Request) => {
  const dnt = request.headers.get("dnt") || request.headers.get("DNT");
  const gpc = request.headers.get("sec-gpc");
  return dnt === "1" || gpc === "1";
};

export async function POST(request: NextRequest) {
  if (isPrivacyOptOut(request)) {
    return new Response(null, { status: 204 });
  }
  const json = await request.json().catch(() => null);
  const parsed = bodySchema.safeParse(json);
  if (!parsed.success) {
    return new Response(`Invalid: ${parsed.error.message}`, { status: 400 });
  }
  const ua = request.headers.get("user-agent") ?? undefined;
  const country = request.headers.get("cf-ipcountry") ?? undefined;

  writeEvent({
    type: "cms.web-vital",
    metric: parsed.data.name,
    numericValue: parsed.data.value,
    navigationType: parsed.data.navigationType,
    route: parsed.data.page,
    owner: parsed.data.owner ?? null,
    repo: parsed.data.repo ?? null,
    branch: parsed.data.branch ?? null,
    userAgent: ua,
    country,
    resourceType: "web-vital",
    resourceId: parsed.data.id,
  });

  return new Response(null, { status: 204 });
}
