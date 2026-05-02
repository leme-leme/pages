import { type NextRequest } from "next/server";
import { z } from "zod";
import { and, eq, sql } from "drizzle-orm";
import { db } from "@/db";
import { projectStorageConfigTable } from "@/db/schema";
import { requireApiUserSession } from "@/lib/session-server";
import { requirePermission } from "@/lib/authz-server";
import { encryptStorageCreds, getStorageConfig } from "@/lib/storage/s3";
import { recordAuditEvent } from "@/lib/audit";
import { createHttpError, toErrorResponse } from "@/lib/api-error";

const writeSchema = z.object({
  endpoint: z.string().url(),
  region: z.string().default("us-east-1"),
  bucket: z.string().min(1),
  prefix: z.string().default(""),
  accessKey: z.string().min(1),
  secretKey: z.string().min(1),
  forcePathStyle: z.boolean().default(true),
  visibility: z.enum(["public", "private"]).default("public"),
  thresholdBytes: z.number().int().positive().default(26214400),
  maxFileBytes: z.number().int().min(-1).default(-1),
  publicBaseUrl: z.string().url().optional().nullable(),
  branch: z.string().optional(),
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

    const cfg = await getStorageConfig(params.owner, params.repo, params.branch);
    return Response.json({
      status: "success",
      data: cfg
        ? {
            endpoint: cfg.endpoint,
            region: cfg.region,
            bucket: cfg.bucket,
            prefix: cfg.prefix,
            forcePathStyle: cfg.forcePathStyle,
            visibility: cfg.visibility,
            thresholdBytes: cfg.thresholdBytes,
            maxFileBytes: cfg.maxFileBytes,
            publicBaseUrl: cfg.publicBaseUrl,
            source: cfg.source,
            // never return the credentials
            hasAccessKey: !!cfg.accessKey,
            hasSecretKey: !!cfg.secretKey,
          }
        : null,
    });
  } catch (error: any) {
    console.error(error);
    return toErrorResponse(error);
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
    const enc = await encryptStorageCreds(parsed.data.accessKey, parsed.data.secretKey);
    const lowerOwner = params.owner.toLowerCase();
    const lowerRepo = params.repo.toLowerCase();

    await db.insert(projectStorageConfigTable)
      .values({
        owner: lowerOwner,
        repo: lowerRepo,
        branch,
        endpoint: parsed.data.endpoint,
        region: parsed.data.region,
        bucket: parsed.data.bucket,
        prefix: parsed.data.prefix,
        forcePathStyle: parsed.data.forcePathStyle,
        visibility: parsed.data.visibility,
        thresholdBytes: parsed.data.thresholdBytes,
        maxFileBytes: parsed.data.maxFileBytes,
        publicBaseUrl: parsed.data.publicBaseUrl ?? null,
        accessKeyCiphertext: enc.accessKeyCiphertext,
        accessKeyIv: enc.accessKeyIv,
        secretKeyCiphertext: enc.secretKeyCiphertext,
        secretKeyIv: enc.secretKeyIv,
      })
      .onConflictDoUpdate({
        target: [
          sql`lower(${projectStorageConfigTable.owner})`,
          sql`lower(${projectStorageConfigTable.repo})`,
          projectStorageConfigTable.branch,
        ],
        set: {
          endpoint: parsed.data.endpoint,
          region: parsed.data.region,
          bucket: parsed.data.bucket,
          prefix: parsed.data.prefix,
          forcePathStyle: parsed.data.forcePathStyle,
          visibility: parsed.data.visibility,
          thresholdBytes: parsed.data.thresholdBytes,
          maxFileBytes: parsed.data.maxFileBytes,
          publicBaseUrl: parsed.data.publicBaseUrl ?? null,
          accessKeyCiphertext: enc.accessKeyCiphertext,
          accessKeyIv: enc.accessKeyIv,
          secretKeyCiphertext: enc.secretKeyCiphertext,
          secretKeyIv: enc.secretKeyIv,
          updatedAt: new Date(),
        },
      });

    await recordAuditEvent({
      actor: { userId: user.id, email: user.email, type: "user" },
      action: "storage.config.update",
      resourceType: "storage-config",
      resourceId: `${lowerOwner}/${lowerRepo}/${branch || "*"}`,
      owner: params.owner,
      repo: params.repo,
      branch: branch || params.branch,
      after: {
        endpoint: parsed.data.endpoint,
        bucket: parsed.data.bucket,
        visibility: parsed.data.visibility,
      },
    });

    return Response.json({ status: "success" });
  } catch (error: any) {
    console.error(error);
    return toErrorResponse(error);
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

    await db.delete(projectStorageConfigTable).where(and(
      sql`lower(${projectStorageConfigTable.owner}) = ${params.owner.toLowerCase()}`,
      sql`lower(${projectStorageConfigTable.repo}) = ${params.repo.toLowerCase()}`,
      eq(projectStorageConfigTable.branch, params.branch ?? ""),
    ));

    await recordAuditEvent({
      actor: { userId: user.id, email: user.email, type: "user" },
      action: "storage.config.delete",
      resourceType: "storage-config",
      resourceId: `${params.owner}/${params.repo}/${params.branch || "*"}`,
      owner: params.owner,
      repo: params.repo,
      branch: params.branch,
    });

    return Response.json({ status: "success" });
  } catch (error: any) {
    console.error(error);
    return toErrorResponse(error);
  }
}
