import { writeFns } from "@/fields/registry";
import { deepMap, generateZodSchema, getSchemaByName, sanitizeObject } from "@/lib/schema";
import { stringify } from "@/lib/serialization";
import { getConfig } from "@/lib/utils/config";
import { normalizePath } from "@/lib/utils/file";
import { createOctokitInstance } from "@/lib/utils/octokit";
import { getAuth } from "@/lib/auth";
import { getToken } from "@/lib/token";
import { updateFileCache } from "@/lib/githubCache";

/**
 * Batch update multiple files in a single commit.
 *
 * POST /api/[owner]/[repo]/[branch]/files-batch
 * Body: { name: string, message: string, updates: Array<{ path, sha, content }> }
 */
export async function POST(
  request: Request,
  { params }: { params: { owner: string; repo: string; branch: string } }
) {
  try {
    const { user, session } = await getAuth();
    if (!session) return new Response(null, { status: 401 });

    const token = await getToken(user, params.owner, params.repo);
    if (!token) throw new Error("Token not found");

    const config = await getConfig(params.owner, params.repo, params.branch);
    if (!config) throw new Error(`Configuration not found.`);

    const data: any = await request.json();
    const { name, message, updates } = data;

    if (!name || !Array.isArray(updates) || updates.length === 0) {
      throw new Error("Invalid request: name and updates array required");
    }

    const schema = getSchemaByName(config.object, name);
    if (!schema) throw new Error(`Schema not found for "${name}"`);

    const octokit = createOctokitInstance(token);

    // Serialize all files and create blobs in parallel
    const blobs = await Promise.all(updates.map(async (update) => {
      const normalizedPath = normalizePath(update.path);

      let contentObject = update.content;
      let contentFields = schema.fields;
      if (schema.list) {
        contentObject = { listWrapper: update.content };
        contentFields = [{ name: "listWrapper", type: "object", list: true, fields: schema.fields }];
      }

      const zodSchema = generateZodSchema(contentFields, false, config.object);
      const zodValidation = zodSchema.safeParse(contentObject);
      if (!zodValidation.success) {
        const errs = zodValidation.error.errors.map((e: any) =>
          `${e.message}${e.path.length ? ` at ${e.path.join(".")}` : ""}`
        );
        throw new Error(`Validation failed for ${normalizedPath}: ${errs.join(", ")}`);
      }

      const validated = deepMap(
        zodValidation.data,
        contentFields,
        (value: any, field: any) => {
          const fieldType = field.type as string;
          return writeFns[fieldType] ? writeFns[fieldType](value, field, config) : value;
        }
      );

      const unwrapped = schema.list ? validated.listWrapper : validated;
      const text = stringify(sanitizeObject(JSON.parse(JSON.stringify(unwrapped))), {
        format: schema.format,
        delimiters: schema.delimiters,
      });
      const contentBase64 = Buffer.from(text).toString("base64");

      const blobRes = await octokit.rest.git.createBlob({
        owner: params.owner,
        repo: params.repo,
        content: contentBase64,
        encoding: "base64",
      });

      return { path: normalizedPath, blobSha: blobRes.data.sha, text };
    }));

    // Get current branch tip
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

    // Create a single new tree with all file changes
    const treeRes = await octokit.rest.git.createTree({
      owner: params.owner,
      repo: params.repo,
      base_tree: baseTreeSha,
      tree: blobs.map((b) => ({
        path: b.path,
        mode: "100644" as const,
        type: "blob" as const,
        sha: b.blobSha,
      })),
    });

    // Create one commit
    const newCommitRes = await octokit.rest.git.createCommit({
      owner: params.owner,
      repo: params.repo,
      message: message || `Reorder ${name} (via Pages CMS)`,
      tree: treeRes.data.sha,
      parents: [currentCommitSha],
    });

    // Advance branch ref
    await octokit.rest.git.updateRef({
      owner: params.owner,
      repo: params.repo,
      ref: `heads/${params.branch}`,
      sha: newCommitRes.data.sha,
    });

    // Update cache for all modified files in parallel
    await Promise.all(blobs.map((blob) =>
      updateFileCache("collection", params.owner, params.repo, params.branch, {
        type: "modify",
        path: blob.path,
        sha: blob.blobSha,
        content: blob.text,
        size: Buffer.byteLength(blob.text),
        commit: { sha: newCommitRes.data.sha, timestamp: Date.now() },
      })
    ));

    return Response.json({
      status: "success",
      message: `${blobs.length} file(s) updated in one commit.`,
      data: { commitSha: newCommitRes.data.sha },
    });
  } catch (error: any) {
    console.error(error);
    return Response.json({ status: "error", message: error.message });
  }
}
