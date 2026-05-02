import { type NextRequest } from "next/server";
import { and, eq, sql } from "drizzle-orm";
import { db } from "@/db";
import { collaboratorTable, collaboratorGrantTable } from "@/db/schema";
import { requirePermission } from "@/lib/authz-server";
import { createHttpError, toErrorResponse } from "@/lib/api-error";
import { requireApiUserSession } from "@/lib/session-server";

export async function GET(
  _request: NextRequest,
  context: { params: Promise<{ slug: string[] }> },
) {
  try {
    const params = await context.params;
    const sessionResult = await requireApiUserSession();
    if ("response" in sessionResult) return sessionResult.response;

    if (!params.slug || params.slug.length !== 2) {
      throw createHttpError("Invalid slug: owner and repo are mandatory", 400);
    }

    const owner = params.slug[0];
    const repo = params.slug[1];

    await requirePermission(sessionResult.user, owner, repo, "admin");

    const collaborators = await db.query.collaboratorTable.findMany({
      where: and(
        sql`lower(${collaboratorTable.owner}) = lower(${owner})`,
        sql`lower(${collaboratorTable.repo}) = lower(${repo})`,
      ),
    });

    const grantsByCollaborator = collaborators.length === 0
      ? {}
      : await loadGrantsByCollaborator(collaborators.map((c) => c.id));

    return Response.json({
      status: "success",
      data: collaborators.map((c) => ({
        ...c,
        grants: grantsByCollaborator[c.id] ?? [],
      })),
    });
  } catch (error: any) {
    console.error(error);
    return toErrorResponse(error);
  }
}

async function loadGrantsByCollaborator(ids: number[]) {
  // Chunk to stay under the D1 ~100-parameter limit.
  const map: Record<number, { scopeType: string; scopeValue: string; permission: string }[]> = {};
  for (let i = 0; i < ids.length; i += 90) {
    const slice = ids.slice(i, i + 90);
    const rows = await db.query.collaboratorGrantTable.findMany({
      where: (t, { inArray }) => inArray(t.collaboratorId, slice),
    });
    for (const row of rows) {
      (map[row.collaboratorId] ||= []).push({
        scopeType: row.scopeType,
        scopeValue: row.scopeValue,
        permission: row.permission,
      });
    }
  }
  // Suppress unused
  void collaboratorGrantTable;
  return map;
}
