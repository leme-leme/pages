import { type NextRequest } from "next/server";
import { z } from "zod";
import { requireApiUserSession } from "@/lib/session-server";
import { createApiToken, listApiTokens, revokeApiToken } from "@/lib/api-tokens";
import { recordAuditEvent } from "@/lib/audit";
import { createHttpError, toErrorResponse } from "@/lib/api-error";

const createSchema = z.object({
  name: z.string().min(1),
  owner: z.string().optional(),
  repo: z.string().optional(),
  branch: z.string().optional(),
  role: z.enum(["owner", "editor", "author", "viewer"]).optional(),
  scopes: z.array(z.object({
    scopeType: z.enum(["collection", "file", "media"]),
    scopeValue: z.string().min(1),
    permission: z.enum(["read", "write", "publish", "admin"]).default("write"),
  })).optional(),
  expiresInDays: z.number().int().positive().optional(),
});

export async function GET() {
  try {
    const sessionResult = await requireApiUserSession();
    if ("response" in sessionResult) return sessionResult.response;
    const tokens = await listApiTokens(sessionResult.user.id);
    return Response.json({
      status: "success",
      data: tokens.map((t) => ({
        id: t.id,
        name: t.name,
        prefix: t.prefix,
        owner: t.owner,
        repo: t.repo,
        branch: t.branch,
        role: t.role,
        lastUsedAt: t.lastUsedAt,
        expiresAt: t.expiresAt,
        revokedAt: t.revokedAt,
        createdAt: t.createdAt,
      })),
    });
  } catch (error: any) {
    console.error(error);
    return toErrorResponse(error);
  }
}

export async function POST(request: NextRequest) {
  try {
    const sessionResult = await requireApiUserSession();
    if ("response" in sessionResult) return sessionResult.response;
    const user = sessionResult.user;

    const parsed = createSchema.safeParse(await request.json());
    if (!parsed.success) throw createHttpError(`Invalid body: ${parsed.error.message}`, 400);

    const expiresAt = parsed.data.expiresInDays
      ? new Date(Date.now() + parsed.data.expiresInDays * 24 * 60 * 60 * 1000)
      : undefined;

    const token = await createApiToken({
      userId: user.id,
      name: parsed.data.name,
      owner: parsed.data.owner,
      repo: parsed.data.repo,
      branch: parsed.data.branch,
      role: parsed.data.role,
      scopes: parsed.data.scopes,
      expiresAt,
    });

    await recordAuditEvent({
      actor: { userId: user.id, email: user.email, type: "user" },
      action: "api-token.create",
      resourceType: "api-token",
      resourceId: String(token.id),
      owner: parsed.data.owner ?? null,
      repo: parsed.data.repo ?? null,
      branch: parsed.data.branch ?? null,
      after: {
        prefix: token.prefix,
        role: parsed.data.role ?? "editor",
        scopes: parsed.data.scopes?.length ?? 0,
        expiresAt: token.expiresAt,
      },
    });

    return Response.json({
      status: "success",
      data: {
        id: token.id,
        token: token.raw, // shown once; never returned again
        prefix: token.prefix,
        expiresAt: token.expiresAt,
      },
    });
  } catch (error: any) {
    console.error(error);
    return toErrorResponse(error);
  }
}

export async function DELETE(request: NextRequest) {
  try {
    const sessionResult = await requireApiUserSession();
    if ("response" in sessionResult) return sessionResult.response;
    const user = sessionResult.user;

    const id = parseInt(new URL(request.url).searchParams.get("id") ?? "", 10);
    if (!Number.isFinite(id)) throw createHttpError("Missing token id", 400);

    await revokeApiToken(user.id, id);
    await recordAuditEvent({
      actor: { userId: user.id, email: user.email, type: "user" },
      action: "api-token.revoke",
      resourceType: "api-token",
      resourceId: String(id),
    });
    return Response.json({ status: "success" });
  } catch (error: any) {
    console.error(error);
    return toErrorResponse(error);
  }
}
