/**
 * S3-compatible storage (MinIO / R2) for media files too large for GitHub.
 * Files are stored in the configured bucket and served via the /api/s3/ proxy.
 *
 * Configuration via Worker env vars (set in wrangler.jsonc vars/secrets):
 *   PAGES_S3_ENDPOINT    e.g. "http://minio:6557" or "https://<account>.r2.cloudflarestorage.com"
 *   PAGES_S3_BUCKET      e.g. "pagescms-media"
 *   PAGES_S3_ACCESS_KEY  required to enable
 *   PAGES_S3_SECRET_KEY  required to enable
 *   PAGES_S3_REGION      default "us-east-1"
 *   PAGES_S3_THRESHOLD   bytes; files larger than this go to S3 (default 25 MB)
 *
 * isS3Configured() gates every other call so the feature is fully opt-in —
 * returns false when access/secret keys aren't set.
 */

import { env } from "cloudflare:workers";
import { S3Client, PutObjectCommand, DeleteObjectCommand, HeadObjectCommand } from "@aws-sdk/client-s3";

const cfg = () => {
  const e = env as unknown as Record<string, string | undefined>;
  return {
    endpoint: e.PAGES_S3_ENDPOINT ?? "http://minio:6557",
    bucket: e.PAGES_S3_BUCKET ?? "pagescms-media",
    accessKey: e.PAGES_S3_ACCESS_KEY ?? "",
    secretKey: e.PAGES_S3_SECRET_KEY ?? "",
    region: e.PAGES_S3_REGION ?? "us-east-1",
  };
};

export const S3_THRESHOLD_BYTES = (() => {
  const e = env as unknown as Record<string, string | undefined>;
  const raw = e.PAGES_S3_THRESHOLD ?? "26214400";
  return parseInt(raw, 10);
})();

export function isS3Configured(): boolean {
  const c = cfg();
  return !!(c.accessKey && c.secretKey);
}

function getClient(): S3Client {
  const c = cfg();
  return new S3Client({
    endpoint: c.endpoint,
    region: c.region,
    credentials: { accessKeyId: c.accessKey, secretAccessKey: c.secretKey },
    forcePathStyle: true,
  });
}

/** S3 key for a media file: {owner}/{repo}/{branch}/{path} */
export function s3Key(owner: string, repo: string, branch: string, path: string): string {
  return `${owner}/${repo}/${branch}/${path.replace(/^\//, "")}`;
}

/** Public URL served via our /api/s3/ proxy */
export function s3PublicUrl(baseUrl: string, key: string): string {
  return `${baseUrl.replace(/\/$/, "")}/api/s3/${key}`;
}

export async function s3Upload(
  owner: string,
  repo: string,
  branch: string,
  path: string,
  body: Uint8Array,
  contentType: string,
): Promise<{ key: string; size: number }> {
  const client = getClient();
  const c = cfg();
  const key = s3Key(owner, repo, branch, path);

  await client.send(new PutObjectCommand({
    Bucket: c.bucket,
    Key: key,
    Body: body,
    ContentType: contentType,
    ContentLength: body.length,
  }));

  return { key, size: body.length };
}

export async function s3Delete(key: string): Promise<void> {
  const client = getClient();
  const c = cfg();
  await client.send(new DeleteObjectCommand({ Bucket: c.bucket, Key: key }));
}

export async function s3Head(key: string): Promise<{ size: number; contentType?: string } | null> {
  try {
    const client = getClient();
    const c = cfg();
    const res = await client.send(new HeadObjectCommand({ Bucket: c.bucket, Key: key }));
    return { size: res.ContentLength ?? 0, contentType: res.ContentType };
  } catch {
    return null;
  }
}

/** Fetch a stored object (used by the proxy route). Returns Response-friendly fields. */
export async function s3Get(key: string): Promise<{ body: ArrayBuffer; contentType: string; size: number } | null> {
  try {
    const c = cfg();
    const url = `${c.endpoint}/${c.bucket}/${key}`;
    const res = await fetch(url);
    if (!res.ok) return null;
    const arrayBuffer = await res.arrayBuffer();
    return {
      body: arrayBuffer,
      contentType: res.headers.get("content-type") ?? "application/octet-stream",
      size: arrayBuffer.byteLength,
    };
  } catch {
    return null;
  }
}
