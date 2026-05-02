/**
 * Public-read proxy for S3-stored media. Maps /api/s3/{owner}/{repo}/{branch}/{...path}
 * to the configured S3 bucket and streams the object back. Returns 404 when S3 isn't
 * configured or the object doesn't exist; relies on the bucket-side ACL for auth.
 */

import { type NextRequest } from "next/server";
import { isS3Configured, s3Get } from "@/lib/storage/s3";

export async function GET(
  _request: NextRequest,
  context: { params: Promise<{ path: string[] }> },
) {
  if (!isS3Configured()) {
    return new Response("S3 storage is not configured", { status: 404 });
  }

  const { path } = await context.params;
  const key = path.map((segment) => decodeURIComponent(segment)).join("/");
  if (!key) return new Response("Bad Request", { status: 400 });

  const obj = await s3Get(key);
  if (!obj) return new Response("Not Found", { status: 404 });

  return new Response(obj.body, {
    status: 200,
    headers: {
      "Content-Type": obj.contentType,
      "Content-Length": String(obj.size),
      "Cache-Control": "public, max-age=300",
    },
  });
}
