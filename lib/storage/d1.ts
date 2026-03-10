/**
 * Cloudflare D1 metadata store for S3-hosted media files.
 * Uses the Cloudflare REST API — no Worker required.
 */

const CF_ACCOUNT_ID  = process.env.CLOUDFLARE_ACCOUNT_ID  ?? "";
const CF_API_TOKEN   = process.env.CLOUDFLARE_API_TOKEN   ?? "";
const D1_DATABASE_ID = process.env.PAGES_D1_DATABASE_ID  ?? "";

const D1_BASE = `https://api.cloudflare.com/client/v4/accounts/${CF_ACCOUNT_ID}/d1/database/${D1_DATABASE_ID}`;

export function isD1Configured(): boolean {
  return !!(CF_ACCOUNT_ID && CF_API_TOKEN && D1_DATABASE_ID);
}

async function d1Query(sql: string, params: any[] = []): Promise<any> {
  const res = await fetch(`${D1_BASE}/query`, {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${CF_API_TOKEN}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ sql, params }),
  });

  const data = await res.json() as any;
  if (!data.success) {
    throw new Error(`D1 error: ${JSON.stringify(data.errors)}`);
  }
  return data.result?.[0];
}

export interface D1MediaFile {
  id: string;
  owner: string;
  repo: string;
  branch: string;
  media_name: string;
  filename: string;
  path: string;
  size: number;
  content_type: string;
  provider: "s3" | "github";
  url: string;
  sha: string | null;
  created_at: string;
}

export async function d1InsertMedia(file: Omit<D1MediaFile, "created_at">): Promise<void> {
  await d1Query(
    `INSERT OR REPLACE INTO media_files
       (id, owner, repo, branch, media_name, filename, path, size, content_type, provider, url, sha)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [file.id, file.owner, file.repo, file.branch, file.media_name, file.filename,
     file.path, file.size, file.content_type, file.provider, file.url, file.sha ?? null],
  );
}

export async function d1GetMedia(owner: string, repo: string, branch: string, path: string): Promise<D1MediaFile | null> {
  const result = await d1Query(
    "SELECT * FROM media_files WHERE owner=? AND repo=? AND branch=? AND path=? LIMIT 1",
    [owner, repo, branch, path],
  );
  return result?.results?.[0] ?? null;
}

export async function d1DeleteMedia(owner: string, repo: string, branch: string, path: string): Promise<void> {
  await d1Query(
    "DELETE FROM media_files WHERE owner=? AND repo=? AND branch=? AND path=?",
    [owner, repo, branch, path],
  );
}

export async function d1ListMedia(owner: string, repo: string, branch: string, mediaName?: string): Promise<D1MediaFile[]> {
  if (mediaName) {
    const result = await d1Query(
      "SELECT * FROM media_files WHERE owner=? AND repo=? AND branch=? AND media_name=? ORDER BY created_at DESC",
      [owner, repo, branch, mediaName],
    );
    return result?.results ?? [];
  }
  const result = await d1Query(
    "SELECT * FROM media_files WHERE owner=? AND repo=? AND branch=? ORDER BY created_at DESC",
    [owner, repo, branch],
  );
  return result?.results ?? [];
}
