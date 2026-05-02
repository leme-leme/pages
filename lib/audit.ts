import { db } from "@/db";
import { auditEventTable } from "@/db/schema";
import { and, desc, eq, sql } from "drizzle-orm";
import { writeEvent } from "@/lib/analytics/collect";
import type { EventType } from "@/lib/analytics/schema";

export type AuditActor = {
  type?: "user" | "api_token" | "system";
  userId?: string | null;
  email?: string | null;
};

export type AuditEventInput = {
  actor: AuditActor;
  action: string;
  resourceType: string;
  resourceId?: string | null;
  owner?: string | null;
  repo?: string | null;
  branch?: string | null;
  before?: unknown;
  after?: unknown;
  metadata?: Record<string, unknown> | null;
  ipAddress?: string | null;
  userAgent?: string | null;
};

const stringify = (value: unknown): string | null => {
  if (value === undefined || value === null) return null;
  try {
    return typeof value === "string" ? value : JSON.stringify(value);
  } catch {
    return String(value);
  }
};

export async function recordAuditEvent(input: AuditEventInput): Promise<void> {
  try {
    await db.insert(auditEventTable).values({
      actorUserId: input.actor.userId ?? null,
      actorEmail: input.actor.email ?? null,
      actorType: input.actor.type ?? "user",
      action: input.action,
      resourceType: input.resourceType,
      resourceId: input.resourceId ?? null,
      owner: input.owner ?? null,
      repo: input.repo ?? null,
      branch: input.branch ?? null,
      before: stringify(input.before),
      after: stringify(input.after),
      metadata: stringify(input.metadata ?? null),
      ipAddress: input.ipAddress ?? null,
      userAgent: input.userAgent ?? null,
    });
  } catch (error) {
    // Audit failures should never break the user-facing request.
    console.warn("[audit] failed to write event", error);
  }

  // Mirror to Analytics Engine for time-series. The action string already
  // matches the EventType taxonomy in lib/analytics/schema.ts (cms.entry.create
  // etc.), so we just prefix and forward.
  try {
    const aeType = (`cms.${input.action}`) as EventType;
    const after = (input.after && typeof input.after === "object")
      ? input.after as Record<string, unknown>
      : null;
    const bytesField = after && typeof after.size === "number" ? after.size : undefined;
    writeEvent({
      type: aeType,
      owner: input.owner ?? null,
      repo: input.repo ?? null,
      branch: input.branch ?? null,
      actor: {
        type: input.actor.type ?? "user",
        userId: input.actor.userId ?? null,
        email: input.actor.email ?? null,
      },
      resourceType: input.resourceType,
      resourceId: input.resourceId ?? null,
      bytes: bytesField,
    });
  } catch {
    // never let analytics break audit
  }
}

export async function listAuditEvents(opts: {
  owner?: string;
  repo?: string;
  branch?: string;
  actorUserId?: string;
  action?: string;
  limit?: number;
}) {
  const conditions = [] as any[];
  if (opts.owner) conditions.push(sql`lower(${auditEventTable.owner}) = lower(${opts.owner})`);
  if (opts.repo) conditions.push(sql`lower(${auditEventTable.repo}) = lower(${opts.repo})`);
  if (opts.branch) conditions.push(eq(auditEventTable.branch, opts.branch));
  if (opts.actorUserId) conditions.push(eq(auditEventTable.actorUserId, opts.actorUserId));
  if (opts.action) conditions.push(eq(auditEventTable.action, opts.action));

  return db.query.auditEventTable.findMany({
    where: conditions.length > 0 ? and(...conditions) : undefined,
    orderBy: desc(auditEventTable.createdAt),
    limit: Math.min(opts.limit ?? 100, 500),
  });
}
