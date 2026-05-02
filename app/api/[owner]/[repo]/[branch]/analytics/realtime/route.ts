import { type NextRequest } from "next/server";
import { requireApiUserSession } from "@/lib/session-server";
import { requirePermission } from "@/lib/authz-server";
import { isAnalyticsQueryConfigured, realtimeMinutes } from "@/lib/analytics/query";
import { toErrorResponse } from "@/lib/api-error";

export async function GET(
  _request: NextRequest,
  context: { params: Promise<{ owner: string; repo: string; branch: string }> },
) {
  try {
    const params = await context.params;
    const sessionResult = await requireApiUserSession();
    if ("response" in sessionResult) return sessionResult.response;
    const user = sessionResult.user;

    await requirePermission(user, params.owner, params.repo, "admin", undefined, params.branch);

    if (!isAnalyticsQueryConfigured()) {
      return Response.json({
        status: "success",
        data: { minutes: [], unconfigured: true },
      });
    }

    const minutes = await realtimeMinutes({ owner: params.owner, repo: params.repo }).catch(() => []);
    return Response.json({ status: "success", data: { minutes } });
  } catch (error) {
    return toErrorResponse(error, { route: "/analytics/realtime" });
  }
}
