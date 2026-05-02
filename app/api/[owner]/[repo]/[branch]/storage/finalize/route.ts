import { type NextRequest } from "next/server";
import { z } from "zod";
import { requireApiUserSession } from "@/lib/session-server";
import { requirePermission } from "@/lib/authz-server";
import { getStorageConfig, s3Head, s3PublicUrl } from "@/lib/storage/s3";
import { generateImageVariants, isImage } from "@/lib/storage/image-processing";
import { recordUsage } from "@/lib/storage/usage";
import { recordAuditEvent } from "@/lib/audit";
import { updateFileCache } from "@/lib/github-cache-file";
import { createHttpError, toErrorResponse } from "@/lib/api-error";
import { getBaseUrl } from "@/lib/base-url";
import { normalizePath } from "@/lib/utils/file";

const bodySchema = z.object({
  name: z.string().min(1),
  path: z.string().min(1),
  key: z.string().min(1),
});

// Called by the client after a presigned PUT (or multipart complete) succeeds
// to persist the cache_file row + usage counter + audit event.
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

    const head = await s3Head(cfg, parsed.data.key);
    if (!head) throw createHttpError("Object not found at the specified key.", 404);

    if (cfg.maxFileBytes !== -1 && head.size > cfg.maxFileBytes) {
      // Operator caps tightened after presign was issued; reject + leave object for GC.
      throw createHttpError(
        `Uploaded file exceeds storage size limit of ${(cfg.maxFileBytes / 1024 / 1024).toFixed(0)} MB.`,
        413,
      );
    }

    const normalized = normalizePath(parsed.data.path);
    const url = cfg.visibility === "private"
      ? `${getBaseUrl().replace(/\/$/, "")}/api/s3/${parsed.data.key}`
      : s3PublicUrl(getBaseUrl(), parsed.data.key, cfg.publicBaseUrl);

    await updateFileCache(
      "media",
      params.owner,
      params.repo,
      params.branch,
      {
        type: "add",
        path: normalized,
        sha: parsed.data.key,
        size: head.size,
        downloadUrl: url,
        provider: "s3",
        s3Key: parsed.data.key,
        commit: { sha: "", timestamp: Date.now() },
      } as any,
    );

    await recordUsage(params.owner, params.repo, params.branch, {
      bytesStoredDelta: head.size,
      fileCountDelta: 1,
    });

    await recordAuditEvent({
      actor: { userId: user.id, email: user.email, type: "user" },
      action: "media.upload",
      resourceType: "media",
      resourceId: normalized,
      owner: params.owner,
      repo: params.repo,
      branch: params.branch,
      after: { provider: "s3", key: parsed.data.key, size: head.size, source: "presigned" },
    });

    if (isImage(parsed.data.key)) {
      generateImageVariants(cfg, parsed.data.key)
        .then((result) =>
          recordUsage(params.owner, params.repo, params.branch, {
            bytesStoredDelta: result.written.reduce((sum, v) => sum + v.size, 0),
            fileCountDelta: result.written.length,
          }),
        )
        .catch((error) => console.warn("[finalize] variant generation failed", error));
    }

    return Response.json({
      status: "success",
      data: {
        type: "file",
        sha: null,
        path: normalized,
        size: head.size,
        url,
        provider: "s3",
      },
    });
  } catch (error: any) {
    console.error(error);
    return toErrorResponse(error);
  }
}
