import { type NextRequest } from "next/server";
import { db } from "@/db";
import { cacheFileTable } from "@/db/schema";
import { and, eq } from "drizzle-orm";
import { getStorageConfig, s3Get, s3PresignedGet } from "@/lib/storage/s3";
import { recordUsage } from "@/lib/storage/usage";
import { resolveRepoAccess } from "@/lib/authz-server";
import { hasPermission } from "@/lib/permissions";
import { getServerSession } from "@/lib/session-server";
import { writeEvent } from "@/lib/analytics/collect";

export async function GET(
  _request: NextRequest,
  context: { params: Promise<{ path: string[] }> },
) {
  const { path } = await context.params;
  const key = path.map((segment) => decodeURIComponent(segment)).join("/");
  if (!key) return new Response("Bad Request", { status: 400 });

  const cached = await db.query.cacheFileTable.findFirst({
    where: (t, { eq }) => eq(t.s3Key, key),
  });
  if (!cached) return new Response("Not Found", { status: 404 });

  const cfg = await getStorageConfig(cached.owner, cached.repo, cached.branch);
  if (!cfg) return new Response("S3 storage is not configured for this project.", { status: 404 });

  // Private buckets: gate by repo permission, then 302 to a presigned URL.
  if (cfg.visibility === "private") {
    const session = await getServerSession();
    if (!session?.user) return new Response("Unauthorized", { status: 401 });
    const access = await resolveRepoAccess(
      session.user as any,
      cached.owner,
      cached.repo,
      cached.branch,
    );
    if (access.source === "none" || !hasPermission(access, "read", { type: "media" })) {
      return new Response("Forbidden", { status: 403 });
    }
    const url = await s3PresignedGet(cfg, key);
    void recordUsage(cached.owner, cached.repo, cached.branch, {
      bytesEgressedDelta: cached.size ?? 0,
    });
    writeEvent({
      type: "cms.media.egress",
      owner: cached.owner, repo: cached.repo, branch: cached.branch,
      resourceType: "media", resourceId: key,
      bytes: cached.size ?? 0,
      status: "private",
    });
    return Response.redirect(url, 302);
  }

  const obj = await s3Get(cfg, key);
  if (!obj) return new Response("Not Found", { status: 404 });

  void recordUsage(cached.owner, cached.repo, cached.branch, {
    bytesEgressedDelta: obj.size,
  });
  writeEvent({
    type: "cms.media.egress",
    owner: cached.owner, repo: cached.repo, branch: cached.branch,
    resourceType: "media", resourceId: key,
    bytes: obj.size,
    status: "public",
  });
  void db.update(cacheFileTable)
    .set({ referencedAt: new Date() })
    .where(and(eq(cacheFileTable.provider, "s3"), eq(cacheFileTable.s3Key, key)));

  return new Response(obj.body, {
    status: 200,
    headers: {
      "Content-Type": obj.contentType,
      "Content-Length": String(obj.size),
      "Cache-Control": "public, max-age=300",
    },
  });
}
