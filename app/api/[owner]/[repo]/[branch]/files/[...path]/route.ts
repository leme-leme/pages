import { type NextRequest } from "next/server";
import { createOctokitInstance } from "@/lib/utils/octokit";
import { isContentOperationAllowed } from "@/lib/operations";
import { writeFns } from "@/fields/registry";
import { configVersion, parseConfig, normalizeConfig } from "@/lib/config";
import { stringify, parse } from "@/lib/serialization";
import { deepMap, generateZodSchema, getSchemaByName, sanitizeObject } from "@/lib/schema";
import { getConfig, updateConfig } from "@/lib/config-store";
import { getFileExtension, getFileName, normalizePath, serializedTypes, getParentPath } from "@/lib/utils/file";
import { assertGithubIdentity } from "@/lib/authz-shared";
import { getToken } from "@/lib/token";
import { updateFileCache } from "@/lib/github-cache-file";
import { createHttpError, toErrorResponse } from "@/lib/api-error";
import { getBaseUrl } from "@/lib/base-url";
import { db } from "@/db";
import { getStorageConfig, s3Key, s3Upload, s3PublicUrl, s3Delete } from "@/lib/storage/s3";
import { recordUsage } from "@/lib/storage/usage";
import { recordAuditEvent } from "@/lib/audit";
import { enforce as enforceRateLimit } from "@/lib/rate-limit";
import { requirePermission, resolveRepoAccess } from "@/lib/authz-server";
import { stripUnwritableFields } from "@/lib/field-permissions";
import mergeWith from "lodash.mergewith";
import { buildCommitTokens, resolveCommitIdentity, resolveCommitMessage } from "@/lib/commit-message";
import { requireApiUserSession } from "@/lib/session-server";
import { saveContentCore } from "@/lib/content/save-core";
import { githubSaveFile } from "@/lib/content/github-save-file";

/**
 * Create, update and delete individual files in a GitHub repository.
 * 
 * POST /api/[owner]/[repo]/[branch]/files/[path]
 * DELETE /api/[owner]/[repo]/[branch]/files/[path]
 * 
 * Requires authentication.
 */

export async function POST(
  request: Request,
  context: { params: Promise<{ owner: string, repo: string, branch: string, path: string | string[] }> }
) {
  try {
    const rawParams = await context.params;
    const params = {
      ...rawParams,
      path: Array.isArray(rawParams.path)
        ? rawParams.path.map(decodeURIComponent).join("/")
        : decodeURIComponent(rawParams.path),
    };
    const sessionResult = await requireApiUserSession();
    if ("response" in sessionResult) return sessionResult.response;
    const user = sessionResult.user;

    const { token } = await getToken(user, params.owner, params.repo, true);
    if (!token) throw new Error("Token not found");

    const normalizedPath = normalizePath(params.path);

    const config = await getConfig(params.owner, params.repo, params.branch, {
      getToken: async () => token,
    });
    if (!config && normalizedPath !== ".pages.yml") throw new Error(`Configuration not found for ${params.owner}/${params.repo}/${params.branch}.`);

    const data: any = await request.json();
    const onConflict = data.onConflict === "error" ? "error" : "rename";

    let contentBase64;
    let schema;
    let schemaCommitTemplates: Record<string, string> | undefined;
    let schemaCommitIdentity: "app" | "user" | undefined;

    switch (data.type) {
      case "content": {
        if (!data.name) throw new Error(`"name" is required for content.`);

        schema = getSchemaByName(config?.object, data.name);
        if (!schema) throw new Error(`Content schema not found for ${data.name}.`);
        if (!data.sha && !isContentOperationAllowed("create", { schema })) {
          throw createHttpError(`Creating entries isn't allowed for "${data.name}".`, 403);
        }
        await requirePermission(
          user,
          params.owner,
          params.repo,
          "write",
          { type: "collection", name: data.name },
          params.branch,
        );

        // The content save/serialize/commit pipeline is shared with the
        // scheduling engine (lib/scheduling/run.ts), so it lives in a core.
        const callerAccess = await resolveRepoAccess(
          user,
          params.owner,
          params.repo,
          params.branch,
        );
        const result = await saveContentCore({
          owner: params.owner,
          repo: params.repo,
          branch: params.branch,
          name: data.name,
          path: normalizedPath,
          content: data.content,
          sha: data.sha,
          onConflict,
          token,
          config,
          actor: { userId: user.id, email: user.email ?? null, type: "user" },
          role: callerAccess.role,
          committerUser: { name: user.name, email: user.email },
        });

        return Response.json({
          status: "success",
          message: result.renamed
            ? `File "${normalizedPath}" saved successfully but renamed to "${result.path}" to avoid naming conflict.`
            : `File "${normalizedPath}" saved successfully.`,
          data: {
            type: result.response?.data.content?.type,
            sha: result.sha,
            name: result.response?.data.content?.name,
            path: result.path,
            extension: getFileExtension(result.response?.data.content?.name || ""),
            size: result.response?.data.content?.size,
            url: result.response?.data.content?.download_url,
          },
        });
      }
      case "media":
        if (!data.name) throw new Error(`"name" is required for media.`);

        schema = getSchemaByName(config?.object, data.name, "media");
        if (!schema) throw new Error(`Media schema not found for ${data.name}.`);
        schemaCommitTemplates = schema?.commit?.templates;
        schemaCommitIdentity = schema?.commit?.identity;

        if (!normalizedPath.startsWith(schema.input)) throw new Error(`Invalid path "${params.path}" for media "${data.name}".`);
        
        if (getFileName(normalizedPath) === ".gitkeep") {
          // Folder creation
          contentBase64 = "";
        } else {
          if (
            schema.extensions?.length > 0 &&
            !schema.extensions.includes(getFileExtension(normalizedPath))
          ) throw new Error(`Invalid extension "${getFileExtension(normalizedPath)}" for media.`);

          const declaredSize: number | undefined = typeof data.size === "number" ? data.size : undefined;
          const approxSize = declaredSize ?? Math.floor((data.content?.length ?? 0) * 0.75);
          const storageCfg = await getStorageConfig(params.owner, params.repo, params.branch);
          if (storageCfg) {
            if (storageCfg.maxFileBytes !== -1 && approxSize > storageCfg.maxFileBytes) {
              throw createHttpError(
                `File exceeds storage size limit of ${(storageCfg.maxFileBytes / 1024 / 1024).toFixed(0)} MB.`,
                413,
              );
            }
          }

          await requirePermission(
            user,
            params.owner,
            params.repo,
            "write",
            { type: "media", name: data.name },
            params.branch,
          );

          if (storageCfg && approxSize > storageCfg.thresholdBytes) {
            await enforceRateLimit(`${user.id}:${params.owner}/${params.repo}`, "upload", 1);
            await enforceRateLimit(
              `${user.id}:${params.owner}/${params.repo}`,
              "upload-bytes",
              Math.max(1, Math.floor(approxSize)),
            );

            const fileBytes = Uint8Array.from(atob(data.content), (c) => c.charCodeAt(0));
            const ext = getFileExtension(normalizedPath);
            const mimeTypes: Record<string, string> = {
              jpg: "image/jpeg", jpeg: "image/jpeg", png: "image/png",
              gif: "image/gif", webp: "image/webp", svg: "image/svg+xml",
              mp4: "video/mp4", webm: "video/webm", mov: "video/quicktime",
              pdf: "application/pdf",
            };
            const contentType = mimeTypes[ext] ?? "application/octet-stream";

            const key = s3Key(params.owner, params.repo, params.branch, normalizedPath, storageCfg.prefix);
            const { size } = await s3Upload(storageCfg, key, fileBytes, contentType);
            const url = storageCfg.visibility === "private"
              ? `${getBaseUrl().replace(/\/$/, "")}/api/s3/${key}`
              : s3PublicUrl(getBaseUrl(), key, storageCfg.publicBaseUrl);

            await updateFileCache(
              "media",
              params.owner, params.repo, params.branch,
              {
                type: "add",
                path: normalizedPath,
                sha: key,
                size,
                downloadUrl: url,
                provider: "s3",
                s3Key: key,
                commit: { sha: "", timestamp: Date.now() },
              } as any,
            );

            await recordUsage(params.owner, params.repo, params.branch, {
              bytesStoredDelta: size,
              fileCountDelta: 1,
            });

            await recordAuditEvent({
              actor: { userId: user.id, email: user.email, type: "user" },
              action: "media.upload",
              resourceType: "media",
              resourceId: normalizedPath,
              owner: params.owner,
              repo: params.repo,
              branch: params.branch,
              after: { provider: "s3", key, size },
            });

            return Response.json({
              status: "success",
              message: `File "${normalizedPath}" saved to S3 storage (${(size / 1024 / 1024).toFixed(1)} MB).`,
              data: {
                type: "file",
                sha: null,
                name: getFileName(normalizedPath),
                path: normalizedPath,
                extension: ext,
                size,
                url,
                provider: "s3",
              },
            });
          }

          contentBase64 = data.content;
        }
        break;
      case "settings":
        assertGithubIdentity(user, "Only GitHub users can manage settings.");
        if (normalizedPath !== ".pages.yml") throw new Error(`Invalid path "${params.path}" for settings.`);
        if (!data.sha && !isContentOperationAllowed("create", { scope: "settings" })) {
          throw createHttpError(`Creating the settings file isn't allowed.`, 403);
        }

        contentBase64 = Buffer.from(data.content.body ?? "").toString("base64");
        break;
      default:
        throw new Error(`Invalid type "${data.type}".`);
    }

    const commitIdentity = resolveCommitIdentity({
      configObject: config?.object,
      identityOverride: schemaCommitIdentity,
    });
    const committer = (
      commitIdentity === "user" &&
      user.email
    )
      ? {
          name: user.name?.trim() || user.email,
          email: user.email,
        }
      : undefined;
    
    const response = await githubSaveFile(
      token,
      params.owner,
      params.repo,
      params.branch,
      normalizedPath,
      contentBase64,
      data.sha,
      {
        configObject: config?.object,
        templatesOverride: schemaCommitTemplates,
        contentName: data.name,
        user: user.email || user.name || String(user.id || ""),
        onConflict,
        committer,
      }
    );
  
    const savedPath = response?.data.content?.path;

    let newConfig;
    if (data.type === "settings") {
      const parsedConfig = parseConfig(data.content.body ?? "");
      const configObject = normalizeConfig(parsedConfig.document.toJSON());
      newConfig = {
        owner: params.owner,
        repo: params.repo,
        branch: params.branch,
        sha: response?.data.content?.sha as string,
        version: configVersion ?? "0.0",
        object: configObject
      };
      
      await updateConfig(newConfig);
    }
    
    if (response?.data.content && response?.data.commit) {
      // If the file is successfully saved, update the cache
      await updateFileCache(
        data.type === 'content' ? 'collection' : 'media',
        params.owner,
        params.repo,
        params.branch,
        {
          type: data.sha ? 'modify' : 'add',
          path: response.data.content.path!,
          sha: response.data.content.sha!,
          content: Buffer.from(contentBase64, 'base64').toString('utf-8'),
          size: response.data.content.size,
          downloadUrl: response.data.content.download_url,
          commit: {
            sha: response.data.commit.sha!,
            timestamp: new Date(response.data.commit.committer?.date ?? new Date().toISOString()).getTime()
          }
        }
      );

      await recordAuditEvent({
        actor: { userId: user.id, email: user.email, type: "user" },
        action: data.sha
          ? `${data.type}.update`
          : `${data.type}.create`,
        resourceType: data.type,
        resourceId: response.data.content.path ?? normalizedPath,
        owner: params.owner,
        repo: params.repo,
        branch: params.branch,
        after: {
          sha: response.data.content.sha,
          name: data.name,
          commitSha: response.data.commit.sha,
        },
      });
    }

    return Response.json({
      status: "success",
      message: savedPath !== normalizedPath
        ? `File "${normalizedPath}" saved successfully but renamed to "${savedPath}" to avoid naming conflict.`
        : `File "${normalizedPath}" saved successfully.`,
      data: {
        type: response?.data.content?.type,
        sha: response?.data.content?.sha,
        name: response?.data.content?.name,
        path: savedPath,
        extension: getFileExtension(response?.data.content?.name || ""),
        size: response?.data.content?.size,
        url: response?.data.content?.download_url,
        config: newConfig ?? undefined,
      }
    });
  } catch (error: any) {
    console.error(error);
    return toErrorResponse(error);
  }
};


export async function DELETE(
  request: NextRequest,
  context: { params: Promise<{ owner: string, repo: string, branch: string, path: string | string[] }> }
) {
  try {
    const params = await context.params;
    const sessionResult = await requireApiUserSession();
    if ("response" in sessionResult) return sessionResult.response;
    const user = sessionResult.user;

    const { token } = await getToken(user, params.owner, params.repo, true);
    if (!token) throw new Error("Token not found");

    if (!isContentOperationAllowed("delete", { scope: "settings" }) && params.path === ".pages.yml") {
      throw createHttpError(`Deleting the settings file isn't allowed.`, 403);
    }

    const searchParams = new URL(request.url).searchParams;
    const sha = searchParams.get("sha");
    const type = searchParams.get("type");
    const name = searchParams.get("name");

    if (!type || !["content", "media"].includes(type)) throw new Error(`"type" is required and must be set to "content" or "media".`);
    if (!name && type === "content") throw new Error(`"name" is required.`);
    if (!sha) throw new Error(`"sha" is required.`);

    if (type === "media") {
      const cached = await db.query.cacheFileTable.findFirst({
        where: (t, { and, eq }) =>
          and(
            eq(t.owner, params.owner),
            eq(t.repo, params.repo),
            eq(t.branch, params.branch),
            eq(t.path, normalizePath(params.path)),
          ),
      });
      if (cached?.provider === "s3" && cached.s3Key) {
        await requirePermission(
          user,
          params.owner,
          params.repo,
          "write",
          { type: "media", name: name ?? "*" },
          params.branch,
        );
        await enforceRateLimit(`${user.id}:${params.owner}/${params.repo}`, "delete", 1);
        const storageCfg = await getStorageConfig(params.owner, params.repo, params.branch);
        if (!storageCfg) throw new Error("S3 storage is no longer configured for this project.");
        await s3Delete(storageCfg, cached.s3Key);
        await updateFileCache(
          "media",
          params.owner, params.repo, params.branch,
          { type: "delete", path: normalizePath(params.path) } as any,
        );
        await recordUsage(params.owner, params.repo, params.branch, {
          bytesStoredDelta: -(cached.size ?? 0),
          fileCountDelta: -1,
        });
        await recordAuditEvent({
          actor: { userId: user.id, email: user.email, type: "user" },
          action: "media.delete",
          resourceType: "media",
          resourceId: normalizePath(params.path),
          owner: params.owner,
          repo: params.repo,
          branch: params.branch,
          before: { provider: "s3", key: cached.s3Key, size: cached.size },
        });
        return Response.json({
          status: "success",
          message: `File "${normalizePath(params.path)}" deleted from S3.`,
          data: { type: "file", path: normalizePath(params.path), provider: "s3" },
        });
      }
    }

    const config = await getConfig(params.owner, params.repo, params.branch, {
      getToken: async () => token,
    });
    if (!config) throw new Error(`Configuration not found for ${params.owner}/${params.repo}/${params.branch}.`);

    const normalizedPath = normalizePath(params.path);
    let schema;
    let schemaCommitTemplates: Record<string, string> | undefined;
    let schemaCommitIdentity: "app" | "user" | undefined;

    switch (type) {
      case "content":
        if (!name) throw new Error(`"name" is required for content.`);

        schema = getSchemaByName(config.object, name);
        if (!schema) throw new Error(`Content schema not found for ${name}.`);
        if (!isContentOperationAllowed("delete", { schema })) {
          throw createHttpError(`Deleting entries isn't allowed for "${name}".`, 403);
        }
        schemaCommitTemplates = schema?.commit?.templates;
        schemaCommitIdentity = schema?.commit?.identity;
        
        if (!normalizedPath.startsWith(schema.path)) throw new Error(`Invalid path "${params.path}" for ${type} "${name}".`);
        
        if (schema.subfolders === false && getParentPath(normalizedPath) !== schema.path) {
          throw new Error(`Subfolders are not allowed for collection "${name}".`);
        }
        
        if (getFileExtension(normalizedPath) !== (schema.extension ?? "")) throw new Error(`Invalid extension "${getFileExtension(normalizedPath)}" for ${type} "${name}".`);
        break;
      case "media":
        if (!name) throw new Error(`"name" is required for media.`);

        schema = getSchemaByName(config.object, name, "media");
        if (!schema) throw new Error(`Media schema not found for ${name}.`);
        schemaCommitTemplates = schema?.commit?.templates;
        schemaCommitIdentity = schema?.commit?.identity;

        if (!normalizedPath.startsWith(schema.input)) throw new Error(`Invalid path "${params.path}" for media "${name}".`);

        if (
          schema.extensions?.length > 0 &&
          !schema.extensions.includes(getFileExtension(normalizedPath))
        ) throw new Error(`Invalid extension "${getFileExtension(normalizedPath)}" for media.`);
        break;
    }

    await requirePermission(
      user,
      params.owner,
      params.repo,
      "write",
      { type: type === "media" ? "media" : "collection", name: name ?? undefined },
      params.branch,
    );

    const commitIdentity = resolveCommitIdentity({
      configObject: config.object,
      identityOverride: schemaCommitIdentity,
    });
    const committer = (
      commitIdentity === "user" &&
      user.email
    )
      ? {
          name: user.name?.trim() || user.email,
          email: user.email,
        }
      : undefined;
    
    const octokit = createOctokitInstance(token);
    const response = await octokit.rest.repos.deleteFile({
      owner: params.owner,
      repo: params.repo,
      branch: params.branch,
      path: normalizedPath,
      sha: sha,
      message: resolveCommitMessage({
        configObject: config.object,
        templatesOverride: schemaCommitTemplates,
        action: "delete",
        tokens: buildCommitTokens({
          action: "delete",
          owner: params.owner,
          repo: params.repo,
          branch: params.branch,
          path: normalizedPath,
          contentName: name || undefined,
          user: user.email || user.name || String(user.id || ""),
          userName: committer?.name,
          userEmail: committer?.email,
        }),
      }),
      committer,
    });

    // Update cache after successful deletion
    await updateFileCache(
      type === "content" ? "collection" : "media",
      params.owner,
      params.repo,
      params.branch,
      {
        type: 'delete',
        path: normalizedPath,
        commit: response?.data.commit?.sha
          ? {
              sha: response.data.commit.sha,
              timestamp: new Date(
                response.data.commit.committer?.date ?? new Date().toISOString(),
              ).getTime(),
            }
          : undefined,
      }
    );

    await recordAuditEvent({
      actor: { userId: user.id, email: user.email, type: "user" },
      action: `${type}.delete`,
      resourceType: type,
      resourceId: normalizedPath,
      owner: params.owner,
      repo: params.repo,
      branch: params.branch,
      before: { sha, name },
      metadata: { commitSha: response?.data.commit?.sha },
    });

    return Response.json({
      status: "success",
      message: `File "${normalizedPath}" deleted successfully.`,
      data: {
        sha: response?.data.commit.sha,
        name: response?.data.content?.name,
        path: response?.data.content?.path,
      }
    });
  } catch (error: any) {
    console.error(error);
    return toErrorResponse(error);
  }
};
