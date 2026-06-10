import { getConfig } from "@/lib/config-store";
import { getToken } from "@/lib/token";
import { requireApiUserSession } from "@/lib/session-server";
import { createHttpError, toErrorResponse } from "@/lib/api-error";
import { saveBatchCore } from "@/lib/content/save-batch-core";

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
