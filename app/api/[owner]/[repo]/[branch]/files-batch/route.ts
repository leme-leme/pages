import { writeFns } from "@/fields/registry";
import { deepMap, generateZodSchema, getSchemaByName, sanitizeObject } from "@/lib/schema";
import { stringify } from "@/lib/serialization";
import { getConfig } from "@/lib/config-store";
import { normalizePath } from "@/lib/utils/file";
import { createOctokitInstance } from "@/lib/utils/octokit";
import { getToken } from "@/lib/token";
import { updateFileCache } from "@/lib/github-cache-file";
import { requireApiUserSession } from "@/lib/session-server";
import { createHttpError, toErrorResponse } from "@/lib/api-error";

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

    if (!name || (!Array.isArray(updates)) || (!Array.isArray(deletions))) {
      throw createHttpError("Invalid request: 'name', and array 'updates'/'deletions' required.", 400);
    }
    if (updates.length === 0 && deletions.length === 0) {
      throw createHttpError("Invalid request: provide at least one update or deletion.", 400);
    }

    const schema = getSchemaByName(config.object, name);
    if (!schema) throw createHttpError(`Schema not found for "${name}".`, 404);

    const octokit = createOctokitInstance(token);

    // When strictPaths is provided, only those paths get fatal validation; other
    // paths (e.g. untranslated non-default i18n locales) are written best-effort.
    const normalizedStrictPaths = Array.isArray(strictPaths)
      ? new Set(strictPaths.map((p: string) => normalizePath(p)))
      : null;

    const blobs = await Promise.all(updates.map(async (update: any) => {
      const normalizedPath = normalizePath(update.path);
      const isStrict = normalizedStrictPaths ? normalizedStrictPaths.has(normalizedPath) : true;

      let text: string;
      if (typeof update.rawText === "string") {
        // Pre-serialized payload (e.g. single_file locale-keyed object) — write verbatim.
        text = update.rawText;
      } else {
        let contentObject = update.content;
        let contentFields = schema.fields;
        if (schema.list) {
          contentObject = { listWrapper: update.content };
          contentFields = [{ name: "listWrapper", type: "object", list: true, fields: schema.fields }];
        }

        const zodSchema = generateZodSchema(contentFields, false, config.object);
        const zodValidation = zodSchema.safeParse(contentObject);
        if (!zodValidation.success && isStrict) {
          const errs = zodValidation.error.issues.map((e) =>
            `${e.message}${e.path.length ? ` at ${e.path.join(".")}` : ""}`,
          );
          throw new Error(`Validation failed for ${normalizedPath}: ${errs.join(", ")}`);
        }

        const validated = deepMap(
          zodValidation.success ? zodValidation.data : contentObject,
          contentFields,
          (value: any, field: any) => {
            const fieldType = field.type as string;
            return writeFns[fieldType] ? writeFns[fieldType](value, field, config) : value;
          },
        );

        const unwrapped = schema.list ? validated.listWrapper : validated;
        text = stringify(sanitizeObject(JSON.parse(JSON.stringify(unwrapped))), {
          format: schema.format,
          delimiters: schema.delimiters,
        });
      }

      const blobRes = await octokit.rest.git.createBlob({
        owner: params.owner,
        repo: params.repo,
        content: btoa(unescape(encodeURIComponent(text))),
        encoding: "base64",
      });

      return { path: normalizedPath, blobSha: blobRes.data.sha, text };
    }));

    const normalizedDeletions: string[] = deletions.map((p: string) => normalizePath(p));

    const refRes = await octokit.rest.git.getRef({
      owner: params.owner,
      repo: params.repo,
      ref: `heads/${params.branch}`,
    });
    const currentCommitSha = refRes.data.object.sha;

    const commitRes = await octokit.rest.git.getCommit({
      owner: params.owner,
      repo: params.repo,
      commit_sha: currentCommitSha,
    });
    const baseTreeSha = commitRes.data.tree.sha;

    const treeRes = await octokit.rest.git.createTree({
      owner: params.owner,
      repo: params.repo,
      base_tree: baseTreeSha,
      tree: [
        ...blobs.map((b) => ({
          path: b.path,
          mode: "100644" as const,
          type: "blob" as const,
          sha: b.blobSha,
        })),
        // Deleting a path: a tree entry with a null sha removes it.
        ...normalizedDeletions.map((path) => ({
          path,
          mode: "100644" as const,
          type: "blob" as const,
          sha: null,
        })),
      ],
    });

    const newCommitRes = await octokit.rest.git.createCommit({
      owner: params.owner,
      repo: params.repo,
      message: message || `Reorder ${name} (via Pages CMS)`,
      tree: treeRes.data.sha,
      parents: [currentCommitSha],
    });

    await octokit.rest.git.updateRef({
      owner: params.owner,
      repo: params.repo,
      ref: `heads/${params.branch}`,
      sha: newCommitRes.data.sha,
    });

    await Promise.all([
      ...blobs.map((blob) =>
        updateFileCache("collection", params.owner, params.repo, params.branch, {
          type: "modify",
          path: blob.path,
          sha: blob.blobSha,
          content: blob.text,
          size: new TextEncoder().encode(blob.text).length,
          commit: { sha: newCommitRes.data.sha, timestamp: Date.now() },
        } as any),
      ),
      ...normalizedDeletions.map((path) =>
        updateFileCache("collection", params.owner, params.repo, params.branch, {
          type: "delete",
          path,
          commit: { sha: newCommitRes.data.sha, timestamp: Date.now() },
        } as any),
      ),
    ]);

    const changed = blobs.length + normalizedDeletions.length;
    return Response.json({
      status: "success",
      message: `${changed} file(s) changed in one commit.`,
      data: { commitSha: newCommitRes.data.sha, sha: newCommitRes.data.sha },
    });
  } catch (error: any) {
    console.error(error);
    return toErrorResponse(error);
  }
}
