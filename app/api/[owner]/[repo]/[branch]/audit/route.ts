import { type NextRequest } from "next/server";
import { requireApiUserSession } from "@/lib/session-server";
import { requirePermission } from "@/lib/authz-server";
import { listAuditEvents } from "@/lib/audit";
import { toErrorResponse } from "@/lib/api-error";

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
    const action = url.searchParams.get("action") ?? undefined;
    const actorUserId = url.searchParams.get("actor") ?? undefined;
    const limit = parseInt(url.searchParams.get("limit") ?? "100", 10);

    const events = await listAuditEvents({
      owner: params.owner,
      repo: params.repo,
      branch: params.branch,
      action,
      actorUserId,
      limit,
    });

    return Response.json({
      status: "success",
      data: events.map((event) => ({
        id: event.id,
        action: event.action,
        actorUserId: event.actorUserId,
        actorEmail: event.actorEmail,
        actorType: event.actorType,
        resourceType: event.resourceType,
        resourceId: event.resourceId,
        owner: event.owner,
        repo: event.repo,
        branch: event.branch,
        before: event.before ? safeParse(event.before) : null,
        after: event.after ? safeParse(event.after) : null,
        metadata: event.metadata ? safeParse(event.metadata) : null,
        createdAt: event.createdAt,
      })),
    });
  } catch (error: any) {
    console.error(error);
    return toErrorResponse(error);
  }
}

const safeParse = (value: string) => {
  try { return JSON.parse(value); } catch { return value; }
};
