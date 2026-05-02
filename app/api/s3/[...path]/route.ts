import { type NextRequest } from "next/server";
import { db } from "@/db";
import { getStorageConfig, s3Get } from "@/lib/storage/s3";

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

  const obj = await s3Get(cfg, key);
  if (!obj) return new Response("Not Found", { status: 404 });

  return new Response(obj.body, {
    status: 200,
    headers: {
      "Content-Type": obj.contentType,
      "Content-Length": String(obj.size),
      "Cache-Control": cfg.visibility === "public" ? "public, max-age=300" : "private, max-age=60",
    },
  });
}
