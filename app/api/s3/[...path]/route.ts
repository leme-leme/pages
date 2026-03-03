/**
 * Proxy route: serves media files stored in MinIO to the browser.
 * GET /api/s3/{owner}/{repo}/{branch}/{...path}
 *
 * MinIO is internal-only (not exposed via Cloudflare tunnel), so the
 * Next.js app fetches the object and streams it back with proper headers.
 * The bucket has public-read so no S3 auth is needed for the fetch.
 */

import { s3Get } from "@/lib/storage/s3";
import { getAuth } from "@/lib/auth";

export const dynamic = "force-dynamic";

export async function GET(
  _request: Request,
  { params }: { params: { path: string[] } }
) {
  // Require authenticated session to view media
  const { session } = await getAuth();
  if (!session) return new Response(null, { status: 401 });

  const key = params.path.join("/");
  const file = await s3Get(key);

  if (!file) {
    return new Response("Not found", { status: 404 });
  }

  return new Response(file.body, {
    headers: {
      "Content-Type": file.contentType,
      "Content-Length": String(file.size),
      "Cache-Control": "public, max-age=31536000, immutable",
    },
  });
}
