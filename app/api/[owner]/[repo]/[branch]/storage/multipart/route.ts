import { type NextRequest } from "next/server";
import { z } from "zod";
import { requireApiUserSession } from "@/lib/session-server";
import { requirePermission } from "@/lib/authz-server";
import {
  getStorageConfig,
  s3AbortMultipart,
  s3CompleteMultipart,
  s3CreateMultipart,
  s3Key,
  s3PresignedPart,
} from "@/lib/storage/s3";
import { enforce as enforceRateLimit } from "@/lib/rate-limit";
import { createHttpError, toErrorResponse } from "@/lib/api-error";
import { normalizePath } from "@/lib/utils/file";

const createSchema = z.object({
  action: z.literal("create"),
  name: z.string().min(1),
  path: z.string().min(1),
  contentType: z.string().default("application/octet-stream"),
  size: z.number().int().positive(),
});

const partsSchema = z.object({
  action: z.literal("sign-parts"),
  name: z.string().min(1),
  key: z.string().min(1),
  uploadId: z.string().min(1),
  partNumbers: z.array(z.number().int().positive()).min(1).max(1000),
});

const completeSchema = z.object({
  action: z.literal("complete"),
  name: z.string().min(1),
  key: z.string().min(1),
  uploadId: z.string().min(1),
  parts: z.array(z.object({
    PartNumber: z.number().int().positive(),
    ETag: z.string().min(1),
  })).min(1),
});

const abortSchema = z.object({
  action: z.literal("abort"),
  name: z.string().min(1),
  key: z.string().min(1),
  uploadId: z.string().min(1),
});

const bodySchema = z.discriminatedUnion("action", [
  createSchema,
  partsSchema,
  completeSchema,
  abortSchema,
]);

export async function POST(
  request: NextRequest,
  context: { params: Promise<{ owner: string; repo: string; branch: string }> },
) {
  try {
    const params = await context.params;
    const sessionResult = await requireApiUserSession();
    if ("response" in sessionResult) return sessionResult.response;
    const user = sessionResult.user;

    const parsed = bodySchema.safeParse(await request.json());
    if (!parsed.success) throw createHttpError(`Invalid body: ${parsed.error.message}`, 400);

    await requirePermission(
      user,
      params.owner,
      params.repo,
      "write",
      { type: "media", name: parsed.data.name },
      params.branch,
    );

    const cfg = await getStorageConfig(params.owner, params.repo, params.branch);
    if (!cfg) throw createHttpError("Storage not configured for this project.", 503);

    const userBucket = `${user.id}:${params.owner}/${params.repo}`;

    switch (parsed.data.action) {
      case "create": {
        if (cfg.maxFileBytes !== -1 && parsed.data.size > cfg.maxFileBytes) {
          throw createHttpError(
            `File exceeds storage size limit of ${(cfg.maxFileBytes / 1024 / 1024).toFixed(0)} MB.`,
            413,
          );
        }
        await enforceRateLimit(userBucket, "presign", 1);
        const normalized = normalizePath(parsed.data.path);
        const key = s3Key(params.owner, params.repo, params.branch, normalized, cfg.prefix);
        const uploadId = await s3CreateMultipart(cfg, key, parsed.data.contentType);
        return Response.json({ status: "success", data: { key, uploadId } });
      }
      case "sign-parts": {
        await enforceRateLimit(userBucket, "presign", parsed.data.partNumbers.length);
        const urls = await Promise.all(
          parsed.data.partNumbers.map((partNumber) =>
            s3PresignedPart(cfg, parsed.data.key, parsed.data.uploadId, partNumber)
              .then((url) => ({ partNumber, url })),
          ),
        );
        return Response.json({ status: "success", data: { urls, expiresIn: 1800 } });
      }
      case "complete": {
        await s3CompleteMultipart(
          cfg,
          parsed.data.key,
          parsed.data.uploadId,
          parsed.data.parts.sort((a, b) => a.PartNumber - b.PartNumber),
        );
        return Response.json({ status: "success", data: { key: parsed.data.key } });
      }
      case "abort": {
        await s3AbortMultipart(cfg, parsed.data.key, parsed.data.uploadId);
        return Response.json({ status: "success" });
      }
    }
  } catch (error: any) {
    console.error(error);
    return toErrorResponse(error);
  }
}
