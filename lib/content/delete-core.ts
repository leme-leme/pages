import { createOctokitInstance } from "@/lib/utils/octokit";
import { withBranchMovedRetry } from "@/lib/github-retry";
import { isContentOperationAllowed } from "@/lib/operations";
import { getSchemaByName } from "@/lib/schema";
import { getFileExtension, normalizePath, getParentPath } from "@/lib/utils/file";
import { updateFileCache } from "@/lib/github-cache-file";
import { createHttpError } from "@/lib/api-error";
import { recordAuditEvent } from "@/lib/audit";
import { buildCommitTokens, resolveCommitIdentity, resolveCommitMessage } from "@/lib/commit-message";
import type { SaveActor } from "@/lib/content/save-core";

export type DeleteContentInput = {
  owner: string;
  repo: string;
  branch: string;
  name: string; // schema/collection name
  path: string; // entry path (normalized internally)
  sha?: string; // resolved from the repo if omitted
  token: string;
  config: { object?: Record<string, any> } | null;
  actor: SaveActor;
  committerUser?: { name?: string | null; email?: string | null };
  auditAction?: string;
  auditMetadata?: Record<string, unknown> | null;
};

export type DeleteContentResult = {
  path: string;
  commitSha: string | null;
};

/**
 * Delete a content entry from GitHub, update the file cache, and record an
 * audit event. Shared by the scheduling engine; mirrors the DELETE files
 * route's content branch.
 */
export async function deleteContentCore(input: DeleteContentInput): Promise<DeleteContentResult> {
  const { owner, repo, branch, name, token, config, actor } = input;
  const normalizedPath = normalizePath(input.path);

  if (!config?.object) throw new Error(`Configuration not found for ${owner}/${repo}/${branch}.`);

  const schema = getSchemaByName(config.object, name);
  if (!schema) throw new Error(`Content schema not found for ${name}.`);
  if (!isContentOperationAllowed("delete", { schema })) {
    throw createHttpError(`Deleting entries isn't allowed for "${name}".`, 403);
  }
  if (!normalizedPath.startsWith(schema.path)) {
    throw new Error(`Invalid path "${input.path}" for content "${name}".`);
  }
  if (schema.subfolders === false && getParentPath(normalizedPath) !== schema.path) {
    throw new Error(`Subfolders are not allowed for collection "${name}".`);
  }
  if (getFileExtension(normalizedPath) !== (schema.extension ?? "")) {
    throw new Error(`Invalid extension "${getFileExtension(normalizedPath)}" for content "${name}".`);
  }

  const octokit = createOctokitInstance(token);

  // Resolve the current sha when the caller didn't pass one (the stored sha
  // can be stale by fire time). Missing file → nothing to delete.
  let sha = input.sha;
  if (!sha) {
    try {
      const response = await octokit.rest.repos.getContent({ owner, repo, path: normalizedPath, ref: branch });
      if (!Array.isArray(response.data) && response.data.type === "file") {
        sha = response.data.sha;
      }
    } catch (error: any) {
      if (error?.status === 404) {
        return { path: normalizedPath, commitSha: null };
      }
      throw error;
    }
  }
  if (!sha) return { path: normalizedPath, commitSha: null };

  const commitIdentity = resolveCommitIdentity({
    configObject: config.object,
    identityOverride: schema?.commit?.identity,
  });
  const committer = (
    commitIdentity === "user" &&
    input.committerUser?.email
  )
    ? {
        name: input.committerUser.name?.trim() || input.committerUser.email,
        email: input.committerUser.email,
      }
    : undefined;

  const response = await withBranchMovedRetry(() => octokit.rest.repos.deleteFile({
    owner,
    repo,
    branch,
    path: normalizedPath,
    sha,
    message: resolveCommitMessage({
      configObject: config.object,
      templatesOverride: schema?.commit?.templates,
      action: "delete",
      tokens: buildCommitTokens({
        action: "delete",
        owner,
        repo,
        branch,
        path: normalizedPath,
        contentName: name,
        user: actor.email || (actor.type === "system" ? "Pages CMS" : ""),
        userName: committer?.name,
        userEmail: committer?.email,
      }),
    }),
    committer,
  }));

  await updateFileCache(
    "collection",
    owner,
    repo,
    branch,
    {
      type: "delete",
      path: normalizedPath,
      commit: response?.data.commit?.sha
        ? {
            sha: response.data.commit.sha,
            timestamp: new Date(
              response.data.commit.committer?.date ?? new Date().toISOString(),
            ).getTime(),
          }
        : undefined,
    } as any,
  );

  await recordAuditEvent({
    actor: { userId: actor.userId, email: actor.email, type: actor.type },
    action: input.auditAction ?? "content.delete",
    resourceType: "content",
    resourceId: normalizedPath,
    owner,
    repo,
    branch,
    before: { sha, name },
    metadata: { commitSha: response?.data.commit?.sha, ...(input.auditMetadata ?? {}) },
  });

  return { path: normalizedPath, commitSha: response?.data.commit?.sha ?? null };
}
