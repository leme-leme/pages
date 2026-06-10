import { Cron } from "croner";
import { and, asc, eq, lte, lt, sql } from "drizzle-orm";
import { db } from "@/db";
import { scheduledJobTable } from "@/db/schema";
import { getInstallationTokenUncached } from "@/lib/token";
import { getConfig } from "@/lib/config-store";
import { getSchemaByName } from "@/lib/schema";
import { createOctokitInstance } from "@/lib/utils/octokit";
import { recordAuditEvent } from "@/lib/audit";
import { saveContentCore, type SaveActor } from "@/lib/content/save-core";
import { deleteContentCore } from "@/lib/content/delete-core";
import { saveBatchCore } from "@/lib/content/save-batch-core";

const SYSTEM_ACTOR: SaveActor = { userId: null, email: null, type: "system" };

// Jobs that have been "running" longer than this are assumed dead (worker died
// mid-execution) and get reset to pending at the top of each poll.
const STUCK_RUNNING_MS = 15 * 60 * 1000;
// Backoff before a transient failure is retried.
const RETRY_BACKOFF_MS = 5 * 60 * 1000;

/** Errors that should not be retried (config/schema gone, app uninstalled, …). */
export class NonRetryableScheduleError extends Error {}

type ScheduledJob = typeof scheduledJobTable.$inferSelect;

/** Resolve the current sha of a file, or undefined if it doesn't exist. */
async function resolveCurrentSha(
  octokit: ReturnType<typeof createOctokitInstance>,
  owner: string,
  repo: string,
  branch: string,
  path: string,
): Promise<string | undefined> {
  try {
    const response = await octokit.rest.repos.getContent({ owner, repo, path, ref: branch });
    if (!Array.isArray(response.data) && response.data.type === "file") {
      return response.data.sha;
    }
  } catch (error: any) {
    if (error?.status === 404) return undefined;
    throw error;
  }
  return undefined;
}

/** Set the configured draft field on a content object (for "unpublish"). */
function applyDraftField(content: any, schema: any): any {
  if (!content || typeof content !== "object" || Array.isArray(content)) {
    throw new NonRetryableScheduleError("Unpublish is only supported for single-entry content.");
  }
  const fields: any[] = Array.isArray(schema?.fields) ? schema.fields : [];
  if (fields.some((f) => f?.name === "status")) {
    return { ...content, status: "draft" };
  }
  if (fields.some((f) => f?.name === "published")) {
    return { ...content, published: false };
  }
  throw new NonRetryableScheduleError(
    `Collection "${schema?.name}" has no "status" or "published" field to unpublish.`,
  );
}

const SCHEDULED_AUDIT_ACTION: Record<string, string> = {
  publish: "content.publish.scheduled",
  unpublish: "content.unpublish.scheduled",
  delete: "content.delete.scheduled",
};

/** Execute a single claimed job. Throws on failure. */
async function executeJob(job: ScheduledJob): Promise<void> {
  let token: string;
  try {
    token = await getInstallationTokenUncached(job.owner, job.repo);
  } catch (error: any) {
    throw new NonRetryableScheduleError(
      `GitHub App installation token unavailable for ${job.owner}/${job.repo}: ${error?.message ?? error}`,
    );
  }

  const config = await getConfig(job.owner, job.repo, job.branch, {
    getToken: async () => token,
  });
  if (!config) {
    throw new NonRetryableScheduleError(
      `Configuration not found for ${job.owner}/${job.repo}/${job.branch}.`,
    );
  }

  const payload: any = job.payload ?? {};
  const auditAction = SCHEDULED_AUDIT_ACTION[job.action] ?? `content.${job.action}.scheduled`;
  const auditMetadata = { jobId: job.id, scheduleKind: job.scheduleKind, attempt: job.attempts };

  // i18n / multi-file jobs go through the batch path (publish across locales,
  // or delete every locale's file in one commit).
  if (job.isBatch) {
    const result = await saveBatchCore({
      owner: job.owner,
      repo: job.repo,
      branch: job.branch,
      name: payload.name ?? job.schemaName,
      message: payload.message,
      updates: payload.updates ?? [],
      deletions: payload.deletions ?? [],
      strictPaths: payload.strictPaths,
      token,
      config,
    });
    await recordAuditEvent({
      actor: SYSTEM_ACTOR,
      action: auditAction,
      resourceType: "content",
      resourceId: job.targetPath,
      owner: job.owner,
      repo: job.repo,
      branch: job.branch,
      after: { commitSha: result.commitSha, changed: result.changed },
      metadata: auditMetadata,
    });
    return;
  }

  if (job.action === "delete") {
    await deleteContentCore({
      owner: job.owner,
      repo: job.repo,
      branch: job.branch,
      name: job.schemaName,
      path: job.targetPath,
      // sha omitted → deleteContentCore resolves the current sha (handles drift).
      token,
      config,
      actor: SYSTEM_ACTOR,
      auditAction,
      auditMetadata,
    });
    return;
  }

  // publish / unpublish
  const schema = getSchemaByName(config.object, job.schemaName);
  if (!schema) {
    throw new NonRetryableScheduleError(`Content schema not found for "${job.schemaName}".`);
  }

  let content = payload.content;
  if (job.action === "unpublish") {
    content = applyDraftField(content, schema);
  }

  // Re-resolve the sha right before writing so we overwrite the current file
  // (last-writer-wins) rather than failing on a stale snapshot sha.
  const octokit = createOctokitInstance(token);
  const freshSha = await resolveCurrentSha(octokit, job.owner, job.repo, job.branch, job.targetPath);

  await saveContentCore({
    owner: job.owner,
    repo: job.repo,
    branch: job.branch,
    name: job.schemaName,
    path: job.targetPath,
    content,
    sha: freshSha,
    onConflict: "error",
    token,
    config,
    actor: SYSTEM_ACTOR,
    role: "owner",
    auditAction,
    auditMetadata,
  });
}

/** Compute the next fire time for a recurring job. */
function nextRecurringRunAt(job: ScheduledJob, after: Date): Date | null {
  if (!job.cronExpr) return null;
  try {
    const next = new Cron(job.cronExpr, { timezone: job.timezone || "UTC" }).nextRun(after);
    return next ?? null;
  } catch {
    return null;
  }
}

/**
 * Find due scheduled jobs, claim each atomically, and execute. Invoked by the
 * every-5-minutes cron in worker/index.ts.
 */
export async function runDueScheduledJobs(opts?: { limit?: number; now?: Date }): Promise<{
  claimed: number;
  succeeded: number;
  failed: number;
}> {
  const now = opts?.now ?? new Date();
  const limit = opts?.limit ?? 25;

  // Self-heal jobs stuck in "running" (worker died mid-execution).
  const stuckCutoff = new Date(now.getTime() - STUCK_RUNNING_MS);
  await db
    .update(scheduledJobTable)
    .set({ status: "pending", lockedAt: null, updatedAt: now })
    .where(and(eq(scheduledJobTable.status, "running"), lt(scheduledJobTable.lockedAt, stuckCutoff)));

  const due = await db.query.scheduledJobTable.findMany({
    where: and(eq(scheduledJobTable.status, "pending"), lte(scheduledJobTable.runAt, now)),
    orderBy: asc(scheduledJobTable.runAt),
    limit,
  });

  let claimed = 0;
  let succeeded = 0;
  let failed = 0;

  for (const job of due) {
    // Atomic claim: only one poller invocation wins the pending→running flip.
    const won = await db
      .update(scheduledJobTable)
      .set({
        status: "running",
        lockedAt: now,
        attempts: sql`${scheduledJobTable.attempts} + 1`,
        updatedAt: now,
      })
      .where(and(eq(scheduledJobTable.id, job.id), eq(scheduledJobTable.status, "pending")))
      .returning({ id: scheduledJobTable.id });
    if (won.length === 0) continue; // another invocation grabbed it
    claimed++;

    const attemptNumber = job.attempts + 1;

    try {
      await executeJob({ ...job, attempts: attemptNumber });
      succeeded++;

      if (job.scheduleKind === "recurring") {
        const next = nextRecurringRunAt(job, now);
        if (next) {
          await db
            .update(scheduledJobTable)
            .set({ status: "pending", runAt: next, lastRunAt: now, lastError: null, lockedAt: null, updatedAt: now })
            .where(eq(scheduledJobTable.id, job.id));
        } else {
          // Unparseable cron → stop recurring.
          await db
            .update(scheduledJobTable)
            .set({ status: "done", lastRunAt: now, lastError: "Could not compute next run", lockedAt: null, updatedAt: now })
            .where(eq(scheduledJobTable.id, job.id));
        }
      } else {
        await db
          .update(scheduledJobTable)
          .set({ status: "done", lastRunAt: now, lastError: null, lockedAt: null, updatedAt: now })
          .where(eq(scheduledJobTable.id, job.id));
      }
    } catch (error: any) {
      failed++;
      const message = error?.message ? String(error.message) : String(error);
      const nonRetryable = error instanceof NonRetryableScheduleError;
      const exhausted = attemptNumber >= job.maxAttempts;

      if (nonRetryable || exhausted) {
        await db
          .update(scheduledJobTable)
          .set({ status: "failed", lastRunAt: now, lastError: message, lockedAt: null, updatedAt: now })
          .where(eq(scheduledJobTable.id, job.id));
      } else {
        // Transient: back off and retry on a later poll.
        await db
          .update(scheduledJobTable)
          .set({
            status: "pending",
            runAt: new Date(now.getTime() + RETRY_BACKOFF_MS),
            lastRunAt: now,
            lastError: message,
            lockedAt: null,
            updatedAt: now,
          })
          .where(eq(scheduledJobTable.id, job.id));
      }

      await recordAuditEvent({
        actor: SYSTEM_ACTOR,
        action: "schedule.run.failed",
        resourceType: "scheduled_job",
        resourceId: String(job.id),
        owner: job.owner,
        repo: job.repo,
        branch: job.branch,
        metadata: { jobId: job.id, action: job.action, attempt: attemptNumber, nonRetryable, error: message },
      });
      console.warn("[scheduling] job failed", { jobId: job.id, attempt: attemptNumber, nonRetryable, error: message });
    }
  }

  return { claimed, succeeded, failed };
}

/** Delete completed/canceled jobs older than `olderThanDays`. Called by the daily cron. */
export async function pruneScheduledJobs(olderThanDays = 30, now = new Date()): Promise<{ deleted: number }> {
  const cutoff = new Date(now.getTime() - olderThanDays * 24 * 60 * 60 * 1000);
  const res = await db
    .delete(scheduledJobTable)
    .where(
      and(
        sql`${scheduledJobTable.status} in ('done','canceled')`,
        lt(scheduledJobTable.updatedAt, cutoff),
      ),
    )
    .returning({ id: scheduledJobTable.id });
  return { deleted: res.length };
}
