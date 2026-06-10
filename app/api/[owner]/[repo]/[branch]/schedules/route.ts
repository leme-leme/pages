import { db } from "@/db";
import { scheduledJobTable } from "@/db/schema";
import { and, desc, eq } from "drizzle-orm";
import { requireApiUserSession } from "@/lib/session-server";
import { requirePermission } from "@/lib/authz-server";
import { recordAuditEvent } from "@/lib/audit";
import { toErrorResponse } from "@/lib/api-error";
import { validateScheduleInput, type ScheduleInput } from "@/lib/scheduling/schedule-input";

/**
 * Schedule one-off / recurring content updates.
 *
 * POST  /api/[owner]/[repo]/[branch]/schedules   — create a schedule
 * GET   /api/[owner]/[repo]/[branch]/schedules   — list schedules (optional ?name=&path=&status=)
 *
 * Requires authentication. Creating requires "publish" permission on the
 * collection; listing requires "read".
 */
export async function POST(
  request: Request,
  context: { params: Promise<{ owner: string; repo: string; branch: string }> },
) {
  try {
    const params = await context.params;
    const sessionResult = await requireApiUserSession();
    if ("response" in sessionResult) return sessionResult.response;
    const user = sessionResult.user;

    const body = (await request.json()) as ScheduleInput;
    const validated = validateScheduleInput(body);

    await requirePermission(
      user,
      params.owner,
      params.repo,
      "publish",
      { type: "collection", name: validated.schemaName },
      params.branch,
    );

    const [created] = await db
      .insert(scheduledJobTable)
      .values({
        owner: params.owner,
        repo: params.repo,
        branch: params.branch,
        action: validated.action,
        targetPath: validated.targetPath,
        schemaName: validated.schemaName,
        payload: validated.payload,
        isBatch: validated.isBatch,
        scheduleKind: validated.scheduleKind,
        cronExpr: validated.cronExpr,
        timezone: validated.timezone,
        runAt: validated.runAt,
        status: "pending",
        createdByUserId: user.id,
        createdByEmail: user.email ?? null,
      })
      .returning();

    await recordAuditEvent({
      actor: { userId: user.id, email: user.email, type: "user" },
      action: "schedule.create",
      resourceType: "scheduled_job",
      resourceId: String(created.id),
      owner: params.owner,
      repo: params.repo,
      branch: params.branch,
      after: {
        action: created.action,
        path: created.targetPath,
        scheduleKind: created.scheduleKind,
        runAt: created.runAt,
      },
    });

    return Response.json({
      status: "success",
      message: "Schedule created.",
      data: created,
    });
  } catch (error: any) {
    console.error(error);
    return toErrorResponse(error);
  }
}

export async function GET(
  request: Request,
  context: { params: Promise<{ owner: string; repo: string; branch: string }> },
) {
  try {
    const params = await context.params;
    const sessionResult = await requireApiUserSession();
    if ("response" in sessionResult) return sessionResult.response;
    const user = sessionResult.user;

    await requirePermission(user, params.owner, params.repo, "read", undefined, params.branch);

    const searchParams = new URL(request.url).searchParams;
    const name = searchParams.get("name");
    const path = searchParams.get("path");
    const status = searchParams.get("status");

    const conditions = [
      eq(scheduledJobTable.owner, params.owner),
      eq(scheduledJobTable.repo, params.repo),
      eq(scheduledJobTable.branch, params.branch),
    ];
    if (name) conditions.push(eq(scheduledJobTable.schemaName, name));
    if (path) conditions.push(eq(scheduledJobTable.targetPath, path));
    if (status) conditions.push(eq(scheduledJobTable.status, status));

    const jobs = await db.query.scheduledJobTable.findMany({
      where: and(...conditions),
      orderBy: desc(scheduledJobTable.runAt),
      limit: 200,
    });

    return Response.json({ status: "success", message: "ok", data: jobs });
  } catch (error: any) {
    console.error(error);
    return toErrorResponse(error);
  }
}
