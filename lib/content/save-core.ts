import { createOctokitInstance } from "@/lib/utils/octokit";
import { isContentOperationAllowed } from "@/lib/operations";
import { writeFns } from "@/fields/registry";
import { stringify, parse } from "@/lib/serialization";
import { deepMap, generateZodSchema, getSchemaByName, sanitizeObject } from "@/lib/schema";
import {
  getFileExtension,
  getFileName,
  normalizePath,
  serializedTypes,
  getParentPath,
} from "@/lib/utils/file";
import { updateFileCache } from "@/lib/github-cache-file";
import { createHttpError } from "@/lib/api-error";
import { recordAuditEvent } from "@/lib/audit";
import { stripUnwritableFields } from "@/lib/field-permissions";
import { resolveCommitIdentity } from "@/lib/commit-message";
import { githubSaveFile } from "@/lib/content/github-save-file";
import type { Role } from "@/lib/permissions";
import mergeWith from "lodash.mergewith";

export type SaveActor = {
  userId: string | null;
  email: string | null;
  type: "user" | "system";
};

export type SaveContentInput = {
  owner: string;
  repo: string;
  branch: string;
  name: string; // schema/collection name
  path: string; // entry path (normalized internally)
  content: unknown; // same shape as POST /files data.content
  sha?: string;
  onConflict?: "rename" | "error";
  token: string;
  config: { object?: Record<string, any> } | null;
  actor: SaveActor;
  // Role used to strip unwritable fields. Default "owner" (no stripping) — the
  // scheduler runs as a system actor with full write access.
  role?: Role;
  // When commit identity resolves to "user", commit as this person. Omit for
  // system actor → commits as the GitHub App.
  committerUser?: { name?: string | null; email?: string | null };
  // Audit action override (e.g. "content.publish.scheduled"). Defaults to
  // "content.create" / "content.update".
  auditAction?: string;
  auditMetadata?: Record<string, unknown> | null;
};

export type SaveContentResult = {
  path: string;
  sha: string | null;
  commitSha: string | null;
  renamed: boolean;
  response: any;
};

/**
 * Validate + serialize + commit a content entry to GitHub, update the file
 * cache, and record an audit event. Shared by the files HTTP route and the
 * scheduling engine so both go through identical write logic.
 *
 * Does NOT perform permission checks — callers gate access before invoking
 * (the HTTP route via requirePermission; the scheduler at create time).
 */
export async function saveContentCore(input: SaveContentInput): Promise<SaveContentResult> {
  const { owner, repo, branch, name, token, config, actor } = input;
  const role: Role = input.role ?? "owner";
  const onConflict = input.onConflict === "error" ? "error" : "rename";
  const normalizedPath = normalizePath(input.path);

  const schema = getSchemaByName(config?.object, name);
  if (!schema) throw new Error(`Content schema not found for ${name}.`);
  if (!input.sha && !isContentOperationAllowed("create", { schema })) {
    throw createHttpError(`Creating entries isn't allowed for "${name}".`, 403);
  }

  if (!normalizedPath.startsWith(schema.path)) {
    throw new Error(`Invalid path "${input.path}" for content "${name}".`);
  }
  if (schema.subfolders === false && getParentPath(normalizedPath) !== schema.path) {
    throw new Error(`Subfolders are not allowed for collection "${name}".`);
  }

  let contentBase64: string;

  if (getFileName(normalizedPath) === ".gitkeep") {
    // Folder creation
    contentBase64 = "";
  } else {
    if (getFileExtension(normalizedPath) !== (schema.extension ?? "")) {
      throw new Error(`Invalid extension "${getFileExtension(normalizedPath)}" for content "${name}".`);
    }

    if (serializedTypes.includes(schema.format) && schema.fields) {
      let contentFields;
      let contentObject;

      // Wrapping things in listWrapper to deal with lists at the root
      if (schema.list) {
        contentObject = { listWrapper: input.content };
        contentFields = [{
          name: "listWrapper",
          type: "object",
          list: true,
          fields: schema.fields,
        }];
      } else {
        contentObject = input.content;
        contentFields = schema.fields;
      }

      contentObject = stripUnwritableFields(
        contentObject as Record<string, any>,
        contentFields as any,
        role,
        "write",
      );

      const zodSchema = generateZodSchema(contentFields);
      const zodValidation = zodSchema.safeParse(contentObject);

      if (zodValidation.success === false) {
        const errorMessages = zodValidation.error.issues.map((issue) => {
          let message = issue.message;
          if (issue.path.length > 0) message = `${message} at ${issue.path.join(".")}`;
          return message;
        });
        throw new Error(`Content validation failed: ${errorMessages.join(", ")}`);
      }

      const validatedContentObject = deepMap(
        zodValidation.data,
        contentFields,
        (value, field) => {
          const fieldType = field.type as string;
          return writeFns[fieldType] ? writeFns[fieldType](value, field, config || {}) : value;
        },
      );

      const unwrappedContentObject = schema.list
        ? validatedContentObject.listWrapper
        : validatedContentObject;

      let finalContentObject = JSON.parse(JSON.stringify(unwrappedContentObject));

      if (config?.object?.settings?.content?.merge && input.sha && !schema.list) {
        const octokit = createOctokitInstance(token);
        const response = await octokit.rest.repos.getContent({
          owner,
          repo,
          path: normalizedPath,
          ref: branch,
        });

        if (Array.isArray(response.data)) {
          throw new Error("Expected a file but found a directory");
        } else if (response.data.type !== "file") {
          throw new Error("Invalid response type");
        }

        const existingContent = Buffer.from(response.data.content, "base64").toString();
        const existingContentObject = parse(existingContent, { format: schema.format, delimiters: schema.delimiters });

        finalContentObject = mergeWith({}, existingContentObject, unwrappedContentObject, (objValue: any, srcValue: any) => {
          if (Array.isArray(srcValue)) {
            return srcValue;
          }
        });
      }

      const stringifiedContentObject = stringify(
        sanitizeObject(finalContentObject),
        {
          format: schema.format,
          delimiters: schema.delimiters,
        },
      );
      contentBase64 = Buffer.from(stringifiedContentObject).toString("base64");
    } else {
      contentBase64 = Buffer.from((input.content as any)?.body ?? "").toString("base64");
    }
  }

  const commitIdentity = resolveCommitIdentity({
    configObject: config?.object,
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

  const response = await githubSaveFile(
    token,
    owner,
    repo,
    branch,
    normalizedPath,
    contentBase64,
    input.sha,
    {
      configObject: config?.object,
      templatesOverride: schema?.commit?.templates,
      contentName: name,
      user: actor.email || (actor.type === "system" ? "Pages CMS" : ""),
      onConflict,
      committer,
    },
  );

  const savedPath = response?.data.content?.path ?? normalizedPath;

  if (response?.data.content && response?.data.commit) {
    await updateFileCache(
      "collection",
      owner,
      repo,
      branch,
      {
        type: input.sha ? "modify" : "add",
        path: response.data.content.path!,
        sha: response.data.content.sha!,
        content: Buffer.from(contentBase64, "base64").toString("utf-8"),
        size: response.data.content.size,
        downloadUrl: response.data.content.download_url,
        commit: {
          sha: response.data.commit.sha!,
          timestamp: new Date(response.data.commit.committer?.date ?? new Date().toISOString()).getTime(),
        },
      } as any,
    );

    await recordAuditEvent({
      actor: { userId: actor.userId, email: actor.email, type: actor.type },
      action: input.auditAction ?? (input.sha ? "content.update" : "content.create"),
      resourceType: "content",
      resourceId: response.data.content.path ?? normalizedPath,
      owner,
      repo,
      branch,
      after: {
        sha: response.data.content.sha,
        name,
        commitSha: response.data.commit.sha,
      },
      metadata: input.auditMetadata ?? undefined,
    });
  }

  return {
    path: savedPath,
    sha: response?.data.content?.sha ?? null,
    commitSha: response?.data.commit?.sha ?? null,
    renamed: savedPath !== normalizedPath,
    response,
  };
}
