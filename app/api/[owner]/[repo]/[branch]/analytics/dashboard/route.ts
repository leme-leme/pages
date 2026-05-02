import { type NextRequest } from "next/server";
import { requireApiUserSession } from "@/lib/session-server";
import { requirePermission } from "@/lib/authz-server";
import {
  errorsByDay,
  eventsByDay,
  isAnalyticsQueryConfigured,
  storageBytesByDay,
  webVitalsByDay,
} from "@/lib/analytics/query";
import { toErrorResponse } from "@/lib/api-error";

const ALLOWED_INTERVALS = new Set(["1d", "7d", "30d", "90d"]);

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

    if (!isAnalyticsQueryConfigured()) {
      return Response.json({
        status: "success",
        data: { events: [], errors: [], storage: [], webVitals: [], unconfigured: true },
      });
    }

    const url = new URL(request.url);
    const intervalParam = url.searchParams.get("interval") ?? "7d";
    const interval = ALLOWED_INTERVALS.has(intervalParam)
      ? (intervalParam as "1d" | "7d" | "30d" | "90d")
      : "7d";

    const owner = params.owner;
    const repo = params.repo;
    const [events, errors, storage, webVitals] = await Promise.all([
      eventsByDay(interval, { owner, repo }).catch(() => []),
      errorsByDay(interval, { owner, repo }).catch(() => []),
      storageBytesByDay(interval, { owner, repo }).catch(() => []),
      webVitalsByDay(interval, { owner, repo }).catch(() => []),
    ]);

    return Response.json({
      status: "success",
      data: { events, errors, storage, webVitals },
    });
  } catch (error) {
    return toErrorResponse(error, { route: "/analytics/dashboard" });
  }
}
