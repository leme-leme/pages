import { createOctokitInstance } from "@/lib/utils/octokit";
import { createHttpError } from "@/lib/api-error";
import { getSchemaByName } from "@/lib/schema";
import { getFileExtension, normalizePath } from "@/lib/utils/file";
import { updateFileCache } from "@/lib/github-cache-file";
import { isBranchMovedError } from "@/lib/github-retry";

export type MediaBatchFile = {
  path: string;
  /** base64-encoded file body */
  content: string;
  size?: number;
};

export type MediaBatchResult = {
  commitSha: string;
  files: { path: string; sha: string; size: number }[];
};

const MAX_BATCH_FILES = 50;

/**
 * Upload a set of media files as ONE commit via the Git Data API
 * (blobs → tree → commit → ref).
 *
 * One commit per multi-file upload instead of one per file: this avoids
 * GitHub's contents-API replica race under rapid consecutive commits, keeps
 * history readable, and is naturally idempotent — re-writing the same path
 * in a tree replaces the file, no numbered duplicates.
 */
export async function uploadMediaBatchCore(input: {
  owner: string;
  repo: string;
  branch: string;
  mediaName?: string;
  files: MediaBatchFile[];
  message?: string;
  token: string;
  config: { object?: Record<string, any> } | null;
}): Promise<MediaBatchResult> {
  const { owner, repo, branch, token, config } = input;

  if (!config?.object) throw createHttpError("Configuration not found.", 404);
  if (!Array.isArray(input.files) || input.files.length === 0) {
    throw createHttpError("No files provided.", 400);
  }
  if (input.files.length > MAX_BATCH_FILES) {
    throw createHttpError(`Too many files in one batch (max ${MAX_BATCH_FILES}).`, 400);
  }

  const mediaConfig = input.mediaName
    ? getSchemaByName(config.object, input.mediaName, "media")
    : Array.isArray(config.object.media)
      ? config.object.media[0]
      : undefined;
  if (!mediaConfig) {
    throw createHttpError(
      input.mediaName
        ? `No media configuration named "${input.mediaName}" found.`
        : "No media configuration found.",
      404,
    );
  }

  const files = input.files.map((f) => {
    const path = normalizePath(f.path);
    if (!path.startsWith(mediaConfig.input)) {
      throw createHttpError(`Invalid path "${f.path}" for media "${mediaConfig.name}".`, 400);
    }
    if (
      Array.isArray(mediaConfig.extensions) && mediaConfig.extensions.length > 0
      && !mediaConfig.extensions.includes(getFileExtension(path))
    ) {
      throw createHttpError(`Invalid extension for "${f.path}".`, 400);
    }
    if (typeof f.content !== "string" || f.content.length === 0) {
      throw createHttpError(`Missing content for "${f.path}".`, 400);
    }
    return {
      path,
      content: f.content,
      size: typeof f.size === "number" ? f.size : Math.floor(f.content.length * 0.75),
    };
  });

  const octokit = createOctokitInstance(token);

  // Blobs are content-addressed and commit-independent — create them up
  // front so the ref-race retry loop below never re-uploads bytes.
  const blobs = await Promise.all(files.map(async (f) => {
    const res = await octokit.rest.git.createBlob({
      owner,
      repo,
      content: f.content,
      encoding: "base64",
    });
    return { ...f, blobSha: res.data.sha };
  }));

  const message = input.message || `Upload ${files.length} file(s) (via Pages CMS)`;

  // The ref update can race a concurrent commit — rebuild the tree on the
  // fresh head and retry.
  let commitSha = "";
  for (let attempt = 1; ; attempt++) {
    try {
      const refRes = await octokit.rest.git.getRef({ owner, repo, ref: `heads/${branch}` });
      const headSha = refRes.data.object.sha;
      const headCommit = await octokit.rest.git.getCommit({ owner, repo, commit_sha: headSha });
      const treeRes = await octokit.rest.git.createTree({
        owner,
        repo,
        base_tree: headCommit.data.tree.sha,
        tree: blobs.map((b) => ({
          path: b.path,
          mode: "100644" as const,
          type: "blob" as const,
          sha: b.blobSha,
        })),
      });
      const commitRes = await octokit.rest.git.createCommit({
        owner,
        repo,
        message,
        tree: treeRes.data.sha,
        parents: [headSha],
      });
      await octokit.rest.git.updateRef({
        owner,
        repo,
        ref: `heads/${branch}`,
        sha: commitRes.data.sha,
      });
      commitSha = commitRes.data.sha;
      break;
    } catch (error: any) {
      const msg = [error?.response?.data?.message, error?.message]
        .filter((m): m is string => typeof m === "string")
        .join(" ");
      const refRace =
        isBranchMovedError(error)
        || (error?.status === 422 && /fast forward/i.test(msg));
      if (!refRace || attempt >= 5) throw error;
      await new Promise((resolve) => setTimeout(resolve, 750 * attempt));
    }
  }

  const timestamp = Date.now();
  for (const b of blobs) {
    await updateFileCache("media", owner, repo, branch, {
      type: "add",
      path: b.path,
      // media-context cache rows never store file bodies, but updateFileCache
      // requires the key to be present for add/modify
      content: null,
      sha: b.blobSha,
      size: b.size,
      downloadUrl: null,
      commit: { sha: commitSha, timestamp },
    } as any);
  }

  return {
    commitSha,
    files: blobs.map((b) => ({ path: b.path, sha: b.blobSha, size: b.size })),
  };
}
