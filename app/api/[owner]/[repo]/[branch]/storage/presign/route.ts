import { type NextRequest } from "next/server";
import { z } from "zod";
import { requireApiUserSession } from "@/lib/session-server";
import { requirePermission } from "@/lib/authz-server";
import {
  getStorageConfig,
  s3Key,
  s3PresignedPut,
  s3PublicUrl,
} from "@/lib/storage/s3";
import { enforce as enforceRateLimit } from "@/lib/rate-limit";
import { createHttpError, toErrorResponse } from "@/lib/api-error";
import { getBaseUrl } from "@/lib/base-url";
import { normalizePath } from "@/lib/utils/file";

const bodySchema = z.object({
  name: z.string().min(1),
  path: z.string().min(1),
  contentType: z.string().default("application/octet-stream"),
  size: z.number().int().nonnegative(),
});

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
    if (!parsed.success) {
      throw createHttpError(`Invalid body: ${parsed.error.message}`, 400);
    }

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

    if (cfg.maxFileBytes !== -1 && parsed.data.size > cfg.maxFileBytes) {
      throw createHttpError(
        `File exceeds storage size limit of ${(cfg.maxFileBytes / 1024 / 1024).toFixed(0)} MB.`,
        413,
      );
    }

    await enforceRateLimit(`${user.id}:${params.owner}/${params.repo}`, "presign", 1);

    const normalized = normalizePath(parsed.data.path);
    const key = s3Key(params.owner, params.repo, params.branch, normalized, cfg.prefix);
    const uploadUrl = await s3PresignedPut(cfg, key, parsed.data.contentType);
    const publicUrl = cfg.visibility === "private"
      ? `${getBaseUrl().replace(/\/$/, "")}/api/s3/${key}`
      : s3PublicUrl(getBaseUrl(), key, cfg.publicBaseUrl);

    return Response.json({
      status: "success",
      data: {
        uploadUrl,
        method: "PUT",
        headers: { "Content-Type": parsed.data.contentType },
        key,
        publicUrl,
        expiresIn: 600,
      },
    });
  } catch (error: any) {
    console.error(error);
    return toErrorResponse(error);
  }
}
