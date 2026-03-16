/**
 * S3-compatible storage (MinIO) for media files too large for GitHub.
 * Files are stored in the configured bucket and served via the /api/s3/ proxy.
 */

import { S3Client, PutObjectCommand, DeleteObjectCommand, HeadObjectCommand } from "@aws-sdk/client-s3";

const S3_ENDPOINT   = process.env.PAGES_S3_ENDPOINT   ?? "http://minio:6557";
const S3_BUCKET     = process.env.PAGES_S3_BUCKET     ?? "pagescms-media";
const S3_ACCESS_KEY = process.env.PAGES_S3_ACCESS_KEY ?? "";
const S3_SECRET_KEY = process.env.PAGES_S3_SECRET_KEY ?? "";
const S3_REGION     = process.env.PAGES_S3_REGION     ?? "us-east-1";

// Size threshold above which files go to S3 instead of GitHub (default 25 MB)
export const S3_THRESHOLD_BYTES =
  parseInt(process.env.PAGES_S3_THRESHOLD ?? "26214400", 10);

export function isS3Configured(): boolean {
  return !!(S3_ACCESS_KEY && S3_SECRET_KEY);
}

function getClient(): S3Client {
  return new S3Client({
    endpoint: S3_ENDPOINT,
    region: S3_REGION,
    credentials: { accessKeyId: S3_ACCESS_KEY, secretAccessKey: S3_SECRET_KEY },
    forcePathStyle: true, // Required for MinIO
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
  body: Buffer,
  contentType: string,
): Promise<{ key: string; size: number }> {
  const client = getClient();
  const key = s3Key(owner, repo, branch, path);

  await client.send(new PutObjectCommand({
    Bucket: S3_BUCKET,
    Key: key,
    Body: body,
    ContentType: contentType,
    ContentLength: body.length,
  }));

  return { key, size: body.length };
}

export async function s3Delete(key: string): Promise<void> {
  const client = getClient();
  await client.send(new DeleteObjectCommand({ Bucket: S3_BUCKET, Key: key }));
}

export async function s3Head(key: string): Promise<{ size: number; contentType?: string } | null> {
  try {
    const client = getClient();
    const res = await client.send(new HeadObjectCommand({ Bucket: S3_BUCKET, Key: key }));
    return { size: res.ContentLength ?? 0, contentType: res.ContentType };
  } catch {
    return null;
  }
}

/** Fetch a stored object as a Buffer (used by the proxy route) */
export async function s3Get(key: string): Promise<{ body: Buffer; contentType: string; size: number } | null> {
  try {
    // Use raw HTTP GET so we don't need @aws-sdk/client-s3 GetObjectCommand streaming edge cases
    const url = `${S3_ENDPOINT}/${S3_BUCKET}/${key}`;
    const res = await fetch(url, {
      headers: {
        // MinIO with public-read bucket needs no auth for GET
      },
    });
    if (!res.ok) return null;
    const arrayBuffer = await res.arrayBuffer();
    return {
      body: Buffer.from(arrayBuffer),
      contentType: res.headers.get("content-type") ?? "application/octet-stream",
      size: arrayBuffer.byteLength,
    };
  } catch {
    return null;
  }
}
