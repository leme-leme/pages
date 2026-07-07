import { getConfig } from "@/lib/config-store";
import { getToken } from "@/lib/token";
import { requireApiUserSession } from "@/lib/session-server";
import { createHttpError, toErrorResponse } from "@/lib/api-error";
import { saveBatchCore } from "@/lib/content/save-batch-core";
import { uploadMediaBatchCore } from "@/lib/content/media-batch-core";
import { recordAuditEvent } from "@/lib/audit";
import { enforce as enforceRateLimit } from "@/lib/rate-limit";
import { requirePermission } from "@/lib/authz-server";

export async function POST(
  request: Request,
  context: { params: Promise<{ owner: string; repo: string; branch: string }> },
) {
  try {
    const params = await context.params;
    const sessionResult = await requireApiUserSession();
    if ("response" in sessionResult) return sessionResult.response;
    const user = sessionResult.user;

    const { token } = await getToken(user, params.owner, params.repo, true);
    if (!token) throw new Error("Token not found");

    const config = await getConfig(params.owner, params.repo, params.branch, {
      getToken: async () => token,
    });
    if (!config) throw createHttpError(`Configuration not found.`, 404);

    const data: any = await request.json();
    const { name, message, updates = [], deletions = [], strictPaths } = data;

    // Media batch: N uploaded files -> one commit via the Git Data API.
    if (data.type === "media") {
      const files = Array.isArray(data.files) ? data.files : [];

      await requirePermission(
        user,
        params.owner,
        params.repo,
        "write",
        { type: "media", name },
        params.branch,
      );
      await enforceRateLimit(
        `${user.id}:${params.owner}/${params.repo}`,
        "upload",
        Math.max(1, files.length),
      );

      const result = await uploadMediaBatchCore({
        owner: params.owner,
        repo: params.repo,
        branch: params.branch,
        mediaName: name,
        files,
        message,
        token,
        config,
      });

      await recordAuditEvent({
        actor: { userId: user.id, email: user.email, type: "user" },
        action: "media.upload",
        resourceType: "media",
        resourceId: result.files[0]?.path ?? "",
        owner: params.owner,
        repo: params.repo,
        branch: params.branch,
        after: { count: result.files.length, paths: result.files.map((f) => f.path), commit: result.commitSha },
      });

      return Response.json({
        status: "success",
        message: `${result.files.length} file(s) uploaded in one commit.`,
        data: { commitSha: result.commitSha, files: result.files },
      });
    }

    const result = await saveBatchCore({
      owner: params.owner,
      repo: params.repo,
      branch: params.branch,
      name,
      message,
      updates,
      deletions,
      strictPaths,
      token,
      config,
    });

    return Response.json({
      status: "success",
      message: `${result.changed} file(s) changed in one commit.`,
      data: { commitSha: result.commitSha, sha: result.commitSha },
    });
  } catch (error: any) {
    console.error(error);
    return toErrorResponse(error);
  }
}
