import { type NextRequest } from "next/server";
import { requireApiUserSession } from "@/lib/session-server";
import { resolveRepoAccess } from "@/lib/authz-server";
import { getStorageConfig } from "@/lib/storage/s3";
import { toErrorResponse } from "@/lib/api-error";

/**
 * Read-only summary of the project's storage config so the client can pick
 * upload routes (GitHub vs presigned S3) without admin permission.
 */
export async function GET(
  _request: NextRequest,
  context: { params: Promise<{ owner: string; repo: string; branch: string }> },
) {
  try {
    const params = await context.params;
    const sessionResult = await requireApiUserSession();
    if ("response" in sessionResult) return sessionResult.response;

    await resolveRepoAccess(sessionResult.user, params.owner, params.repo, params.branch);

    const cfg = await getStorageConfig(params.owner, params.repo, params.branch);
    return Response.json({
      status: "success",
      data: {
        configured: !!cfg,
        thresholdBytes: cfg?.thresholdBytes ?? 26214400,
        maxFileBytes: cfg?.maxFileBytes ?? -1,
        visibility: cfg?.visibility ?? "public",
        source: cfg?.source ?? null,
      },
    });
  } catch (error: any) {
    console.error(error);
    return toErrorResponse(error);
  }
}
