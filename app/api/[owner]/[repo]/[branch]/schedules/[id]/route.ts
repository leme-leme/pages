import { db } from "@/db";
import { scheduledJobTable } from "@/db/schema";
import { and, eq } from "drizzle-orm";
import { requireApiUserSession } from "@/lib/session-server";
import { requirePermission } from "@/lib/authz-server";
import { recordAuditEvent } from "@/lib/audit";
import { createHttpError, toErrorResponse } from "@/lib/api-error";
import { validateScheduleInput, type ScheduleInput } from "@/lib/scheduling/schedule-input";

type Ctx = { params: Promise<{ owner: string; repo: string; branch: string; id: string }> };

async function loadJob(owner: string, repo: string, branch: string, id: number) {
  const job = await db.query.scheduledJobTable.findFirst({
    where: and(
      eq(scheduledJobTable.id, id),
      eq(scheduledJobTable.owner, owner),
      eq(scheduledJobTable.repo, repo),
      eq(scheduledJobTable.branch, branch),
    ),
  });
  return job ?? null;
}

export async function GET(_request: Request, context: Ctx) {
  try {
    const params = await context.params;
    const sessionResult = await requireApiUserSession();
    if ("response" in sessionResult) return sessionResult.response;
    const user = sessionResult.user;

    await requirePermission(user, params.owner, params.repo, "read", undefined, params.branch);

    const job = await loadJob(params.owner, params.repo, params.branch, Number(params.id));
    if (!job) throw createHttpError("Schedule not found.", 404);

    return Response.json({ status: "success", message: "ok", data: job });
  } catch (error: any) {
    console.error(error);
    return toErrorResponse(error);
  }
}

export async function PATCH(request: Request, context: Ctx) {
  try {
    const params = await context.params;
    const sessionResult = await requireApiUserSession();
    if ("response" in sessionResult) return sessionResult.response;
    const user = sessionResult.user;

    const job = await loadJob(params.owner, params.repo, params.branch, Number(params.id));
    if (!job) throw createHttpError("Schedule not found.", 404);

    await requirePermission(
      user,
      params.owner,
      params.repo,
      "publish",
      { type: "collection", name: job.schemaName },
      params.branch,
    );

    if (job.status !== "pending" && job.status !== "failed") {
      throw createHttpError(`Only pending or failed schedules can be edited (current: ${job.status}).`, 409);
    }

    // Re-validate using the existing job as defaults for fields not supplied.
    const body = (await request.json()) as Partial<ScheduleInput>;
    const merged: ScheduleInput = {
      action: (body.action ?? job.action) as any,
      name: body.name ?? job.schemaName,
      path: body.path ?? job.targetPath,
      payload: body.payload ?? job.payload,
      isBatch: body.isBatch ?? job.isBatch,
      scheduleKind: (body.scheduleKind ?? job.scheduleKind) as any,
      runAt: body.runAt,
      cronExpr: body.cronExpr ?? job.cronExpr ?? undefined,
      timezone: body.timezone ?? job.timezone,
    };
    // For "once" without a new runAt, keep the existing one.
    if (merged.scheduleKind === "once" && !merged.runAt) {
      merged.runAt = job.runAt.toISOString();
    }
    const validated = validateScheduleInput(merged);

    const [updated] = await db
      .update(scheduledJobTable)
      .set({
        action: validated.action,
        targetPath: validated.targetPath,
        schemaName: validated.schemaName,
        payload: validated.payload,
        isBatch: validated.isBatch,
        scheduleKind: validated.scheduleKind,
        cronExpr: validated.cronExpr,
        timezone: validated.timezone,
        runAt: validated.runAt,
        // Re-arm a failed job.
        status: "pending",
        lastError: null,
        updatedAt: new Date(),
      })
      .where(eq(scheduledJobTable.id, job.id))
      .returning();

    await recordAuditEvent({
      actor: { userId: user.id, email: user.email, type: "user" },
      action: "schedule.update",
      resourceType: "scheduled_job",
      resourceId: String(job.id),
      owner: params.owner,
      repo: params.repo,
      branch: params.branch,
      before: { runAt: job.runAt, cronExpr: job.cronExpr, status: job.status },
      after: { runAt: updated.runAt, cronExpr: updated.cronExpr },
    });

    return Response.json({ status: "success", message: "Schedule updated.", data: updated });
  } catch (error: any) {
    console.error(error);
    return toErrorResponse(error);
  }
}

export async function DELETE(_request: Request, context: Ctx) {
  try {
    const params = await context.params;
    const sessionResult = await requireApiUserSession();
    if ("response" in sessionResult) return sessionResult.response;
    const user = sessionResult.user;

    const job = await loadJob(params.owner, params.repo, params.branch, Number(params.id));
    if (!job) throw createHttpError("Schedule not found.", 404);

    await requirePermission(
      user,
      params.owner,
      params.repo,
      "publish",
      { type: "collection", name: job.schemaName },
      params.branch,
    );

    // Soft-cancel: preserve the row for audit/history.
    await db
      .update(scheduledJobTable)
      .set({ status: "canceled", lockedAt: null, updatedAt: new Date() })
      .where(eq(scheduledJobTable.id, job.id));

    await recordAuditEvent({
      actor: { userId: user.id, email: user.email, type: "user" },
      action: "schedule.cancel",
      resourceType: "scheduled_job",
      resourceId: String(job.id),
      owner: params.owner,
      repo: params.repo,
      branch: params.branch,
      before: { status: job.status, runAt: job.runAt },
    });

    return Response.json({ status: "success", message: "Schedule canceled.", data: { id: job.id } });
  } catch (error: any) {
    console.error(error);
    return toErrorResponse(error);
  }
}
