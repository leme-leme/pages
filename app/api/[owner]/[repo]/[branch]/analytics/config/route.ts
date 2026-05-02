import { type NextRequest } from "next/server";
import { z } from "zod";
import { and, eq, sql } from "drizzle-orm";
import { db } from "@/db";
import { projectAnalyticsConfigTable } from "@/db/schema";
import { requireApiUserSession } from "@/lib/session-server";
import { requirePermission } from "@/lib/authz-server";
import { recordAuditEvent } from "@/lib/audit";
import { createHttpError, toErrorResponse } from "@/lib/api-error";

const writeSchema = z.object({
  ga4MeasurementId: z.string().regex(/^G-[A-Z0-9]+$/i).optional().nullable(),
  plausibleDomain: z.string().min(1).optional().nullable(),
  plausibleApiHost: z.string().url().optional().nullable(),
  cfBeaconToken: z.string().regex(/^[a-f0-9]{32}$/i).optional().nullable(),
  requireConsent: z.boolean().default(true),
  honorDnt: z.boolean().default(true),
  branch: z.string().optional(),
});

const findRow = (owner: string, repo: string, branch: string) =>
  db.query.projectAnalyticsConfigTable.findFirst({
    where: and(
      sql`lower(${projectAnalyticsConfigTable.owner}) = ${owner.toLowerCase()}`,
      sql`lower(${projectAnalyticsConfigTable.repo}) = ${repo.toLowerCase()}`,
      eq(projectAnalyticsConfigTable.branch, branch),
    ),
  });

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

    const row = (await findRow(params.owner, params.repo, params.branch))
      ?? (await findRow(params.owner, params.repo, ""));

    return Response.json({
      status: "success",
      data: row ? {
        ga4MeasurementId: row.ga4MeasurementId,
        plausibleDomain: row.plausibleDomain,
        plausibleApiHost: row.plausibleApiHost,
        cfBeaconToken: row.cfBeaconToken,
        requireConsent: !!row.requireConsent,
        honorDnt: !!row.honorDnt,
      } : null,
    });
  } catch (error) {
    return toErrorResponse(error, { route: "/analytics/config" });
  }
}

export async function PUT(
  request: NextRequest,
  context: { params: Promise<{ owner: string; repo: string; branch: string }> },
) {
  try {
    const params = await context.params;
    const sessionResult = await requireApiUserSession();
    if ("response" in sessionResult) return sessionResult.response;
    const user = sessionResult.user;

    await requirePermission(user, params.owner, params.repo, "admin", undefined, params.branch);

    const parsed = writeSchema.safeParse(await request.json());
    if (!parsed.success) throw createHttpError(`Invalid body: ${parsed.error.message}`, 400);

    const branch = parsed.data.branch ?? "";
    const lowerOwner = params.owner.toLowerCase();
    const lowerRepo = params.repo.toLowerCase();

    const existing = await findRow(lowerOwner, lowerRepo, branch);
    if (existing) {
      await db.update(projectAnalyticsConfigTable)
        .set({
          ga4MeasurementId: parsed.data.ga4MeasurementId ?? null,
          plausibleDomain: parsed.data.plausibleDomain ?? null,
          plausibleApiHost: parsed.data.plausibleApiHost ?? null,
          cfBeaconToken: parsed.data.cfBeaconToken ?? null,
          requireConsent: parsed.data.requireConsent,
          honorDnt: parsed.data.honorDnt,
          updatedAt: new Date(),
        })
        .where(eq(projectAnalyticsConfigTable.id, existing.id));
    } else {
      await db.insert(projectAnalyticsConfigTable).values({
        owner: lowerOwner,
        repo: lowerRepo,
        branch,
        ga4MeasurementId: parsed.data.ga4MeasurementId ?? null,
        plausibleDomain: parsed.data.plausibleDomain ?? null,
        plausibleApiHost: parsed.data.plausibleApiHost ?? null,
        cfBeaconToken: parsed.data.cfBeaconToken ?? null,
        requireConsent: parsed.data.requireConsent,
        honorDnt: parsed.data.honorDnt,
      });
    }

    await recordAuditEvent({
      actor: { userId: user.id, email: user.email, type: "user" },
      action: "analytics.config.update",
      resourceType: "analytics-config",
      resourceId: `${lowerOwner}/${lowerRepo}/${branch || "*"}`,
      owner: params.owner,
      repo: params.repo,
      branch: branch || params.branch,
      after: {
        ga4: !!parsed.data.ga4MeasurementId,
        plausible: !!parsed.data.plausibleDomain,
        cf: !!parsed.data.cfBeaconToken,
        requireConsent: parsed.data.requireConsent,
      },
    });

    return Response.json({ status: "success" });
  } catch (error) {
    return toErrorResponse(error, { route: "/analytics/config" });
  }
}

export async function DELETE(
  _request: NextRequest,
  context: { params: Promise<{ owner: string; repo: string; branch: string }> },
) {
  try {
    const params = await context.params;
    const sessionResult = await requireApiUserSession();
    if ("response" in sessionResult) return sessionResult.response;
    const user = sessionResult.user;

    await requirePermission(user, params.owner, params.repo, "admin", undefined, params.branch);

    await db.delete(projectAnalyticsConfigTable).where(and(
      sql`lower(${projectAnalyticsConfigTable.owner}) = ${params.owner.toLowerCase()}`,
      sql`lower(${projectAnalyticsConfigTable.repo}) = ${params.repo.toLowerCase()}`,
      eq(projectAnalyticsConfigTable.branch, params.branch ?? ""),
    ));

    await recordAuditEvent({
      actor: { userId: user.id, email: user.email, type: "user" },
      action: "analytics.config.delete",
      resourceType: "analytics-config",
      resourceId: `${params.owner}/${params.repo}/${params.branch || "*"}`,
      owner: params.owner,
      repo: params.repo,
      branch: params.branch,
    });

    return Response.json({ status: "success" });
  } catch (error) {
    return toErrorResponse(error, { route: "/analytics/config" });
  }
}
