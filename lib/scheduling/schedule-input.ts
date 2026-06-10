import { Cron } from "croner";
import { createHttpError } from "@/lib/api-error";

export const SCHEDULE_ACTIONS = ["publish", "unpublish", "delete"] as const;
export type ScheduleAction = (typeof SCHEDULE_ACTIONS)[number];
export type ScheduleKind = "once" | "recurring";

export type ScheduleInput = {
  action: ScheduleAction;
  name: string;
  path: string;
  payload?: any;
  isBatch?: boolean;
  scheduleKind: ScheduleKind;
  runAt?: string; // ISO, required for "once"
  cronExpr?: string; // required for "recurring"
  timezone?: string;
};

export type ValidatedSchedule = {
  action: ScheduleAction;
  schemaName: string;
  targetPath: string;
  payload: any;
  isBatch: boolean;
  scheduleKind: ScheduleKind;
  cronExpr: string | null;
  timezone: string;
  runAt: Date;
};

/**
 * Validate a create/update request body and compute the first `runAt`.
 * Throws an HTTP error (400) on invalid input.
 */
export function validateScheduleInput(input: ScheduleInput, now = new Date()): ValidatedSchedule {
  const { action, name, path } = input;

  if (!action || !SCHEDULE_ACTIONS.includes(action)) {
    throw createHttpError(`"action" must be one of: ${SCHEDULE_ACTIONS.join(", ")}.`, 400);
  }
  if (!name || typeof name !== "string") throw createHttpError(`"name" is required.`, 400);
  if (!path || typeof path !== "string") throw createHttpError(`"path" is required.`, 400);

  const isBatch = input.isBatch === true;
  const timezone = (input.timezone && String(input.timezone)) || "UTC";

  if (action === "unpublish" && isBatch) {
    throw createHttpError(`Unpublish is not supported for multi-file (i18n) entries.`, 400);
  }

  // Payload checks.
  if (isBatch) {
    const p = input.payload ?? {};
    const hasUpdates = Array.isArray(p.updates) && p.updates.length > 0;
    const hasDeletions = Array.isArray(p.deletions) && p.deletions.length > 0;
    if (!hasUpdates && !hasDeletions) {
      throw createHttpError(`Batch schedule payload requires "updates" or "deletions".`, 400);
    }
  } else if (action === "publish" || action === "unpublish") {
    if (!input.payload || typeof input.payload !== "object" || input.payload.content === undefined) {
      throw createHttpError(`A content payload is required to schedule a ${action}.`, 400);
    }
  }

  let runAt: Date;
  let cronExpr: string | null = null;

  if (input.scheduleKind === "recurring") {
    if (!input.cronExpr || typeof input.cronExpr !== "string") {
      throw createHttpError(`"cronExpr" is required for recurring schedules.`, 400);
    }
    let next: Date | null;
    try {
      next = new Cron(input.cronExpr, { timezone }).nextRun(now);
    } catch (error: any) {
      throw createHttpError(`Invalid cron expression: ${error?.message ?? "parse error"}.`, 400);
    }
    if (!next) throw createHttpError(`Cron expression has no upcoming run time.`, 400);
    cronExpr = input.cronExpr;
    runAt = next;
  } else if (input.scheduleKind === "once") {
    if (!input.runAt) throw createHttpError(`"runAt" is required for one-off schedules.`, 400);
    const parsed = new Date(input.runAt);
    if (Number.isNaN(parsed.getTime())) throw createHttpError(`"runAt" is not a valid date.`, 400);
    if (parsed.getTime() <= now.getTime()) throw createHttpError(`"runAt" must be in the future.`, 400);
    runAt = parsed;
  } else {
    throw createHttpError(`"scheduleKind" must be "once" or "recurring".`, 400);
  }

  return {
    action,
    schemaName: name,
    targetPath: path,
    payload: input.payload ?? null,
    isBatch,
    scheduleKind: input.scheduleKind,
    cronExpr,
    timezone,
    runAt,
  };
}
