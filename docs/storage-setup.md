# Storage setup (S3 / R2)

Pages CMS streams files >25 MB through an S3-compatible backend. The reference
implementations are AWS S3 and Cloudflare R2.

## Per-project config (recommended)

Configure storage in **Project Settings → Storage**. Credentials are encrypted
at rest in D1 with the `CRYPTO_KEY` env var. The same form is reachable via
`PUT /api/[owner]/[repo]/[branch]/storage/config`.

| Field | Notes |
| --- | --- |
| Endpoint | `https://<account>.r2.cloudflarestorage.com` for R2, `https://s3.<region>.amazonaws.com` for S3 |
| Region | R2 ignores this; pick `auto`. AWS uses real region. |
| Bucket | Must already exist. |
| Prefix | Optional. Useful when sharing one bucket across projects. |
| Force path style | `true` for MinIO/R2, `false` for AWS S3 |
| Visibility | `public` = served via the worker proxy (cached). `private` = 302→presigned URL after permission check. |
| Threshold | Files smaller than this go through GitHub. Default 25 MB. |
| Max file bytes | Hard cap (`-1` disables). 413 returned past this limit. |
| Public base URL | Optional CDN/edge URL for public reads (skips the worker). |

## Env-var fallback

If no D1 row matches an `(owner, repo, branch)` tuple, the worker falls back to:

```
PAGES_S3_ENDPOINT
PAGES_S3_REGION
PAGES_S3_BUCKET
PAGES_S3_ACCESS_KEY
PAGES_S3_SECRET_KEY
PAGES_S3_VISIBILITY    # public | private
PAGES_S3_THRESHOLD     # bytes (default 26214400 = 25 MB)
PAGES_S3_MAX_FILE_BYTES  # -1 = unlimited
PAGES_S3_PUBLIC_BASE_URL # optional CDN base
```

## Cloudflare R2 — bucket policy

R2 buckets default to *private*. The CMS doesn't need a public bucket — the
worker proxy enforces visibility. If you set `Visibility = public` in the
project config, the worker proxy serves the object with a 5-minute browser
cache. For private buckets the worker mints a 5-minute presigned GET.

Generate an API token with **Object Read & Write** scoped to the bucket:

1. Cloudflare dashboard → R2 → Manage R2 API Tokens → Create API Token.
2. Permission: Object Read & Write. Bucket: pin to the specific bucket.
3. Save the access key + secret key into the project config.

### R2 CORS (required for direct browser uploads)

Direct uploads (presigned PUT, multipart parts) need CORS so the browser can
read the response and `ETag` header. Apply via the R2 dashboard or
`wrangler r2 bucket cors put`:

```json
[
  {
    "AllowedOrigins": ["https://your-cms.example.com"],
    "AllowedMethods": ["GET", "PUT", "POST", "DELETE", "HEAD"],
    "AllowedHeaders": ["*"],
    "ExposeHeaders": ["ETag"],
    "MaxAgeSeconds": 3600
  }
]
```

## AWS S3 — bucket policy

Recommended: keep the bucket **private** and let the worker proxy/presign.
No public bucket policy is required. If you absolutely want a public bucket
(e.g. paired with CloudFront), use the minimum policy below and set
`Visibility = public` + `Public base URL = https://...cloudfront.net` in the
project config:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "PublicRead",
      "Effect": "Allow",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::your-bucket/*"
    }
  ]
}
```

Create an IAM user with the inline policy below, generate an access key pair,
and paste them into the project config:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:PutObject",
        "s3:GetObject",
        "s3:DeleteObject",
        "s3:ListBucket",
        "s3:AbortMultipartUpload",
        "s3:ListMultipartUploadParts"
      ],
      "Resource": [
        "arn:aws:s3:::your-bucket",
        "arn:aws:s3:::your-bucket/*"
      ]
    }
  ]
}
```

### S3 CORS (required for direct browser uploads)

```json
[
  {
    "AllowedOrigins": ["https://your-cms.example.com"],
    "AllowedMethods": ["GET", "PUT", "POST", "DELETE", "HEAD"],
    "AllowedHeaders": ["*"],
    "ExposeHeaders": ["ETag"],
    "MaxAgeSeconds": 3600
  }
]
```

## Lifecycle / orphan media GC

A daily Cron Trigger (`0 3 * * *`) calls `gcOrphanMedia()` which deletes any
S3-backed `cache_file` row whose `referenced_at` and `updated_at` are both
older than `STORAGE_ORPHAN_AGE_DAYS` (default 30). The S3 object is also
deleted, the row removed, and `storage_usage` decremented.

Override the threshold:

```
STORAGE_ORPHAN_AGE_DAYS=14
```

## S3 → D1 reconciliation

A 30-minute Cron Trigger (`*/30 * * * *`) picks up to 5 distinct
`(owner, repo, branch)` tuples and `ListObjectsV2`-walks the relevant prefix.
Cache rows whose object no longer exists (operator deleted from S3 console,
lifecycle rule expired, etc.) are dropped from D1 and their bytes deducted
from `storage_usage`.

## Image processing

For `jpg/jpeg/png/webp/avif` uploads, finalize spawns three WebP variants via
the Cloudflare `IMAGES` binding:

- `thumb` (240w, q=80)
- `medium` (1024w, q=82)
- `large` (2048w, q=85)

They land at `<key>.variants/<name>.webp` in the same bucket and count toward
`storage_usage.bytesStored`. Failures are logged and the original upload
still succeeds. To disable, omit the `IMAGES` binding from `wrangler.jsonc`.

## Multipart uploads

Files ≥100 MB are uploaded in 8 MB parts via presigned URLs. The client drives
`/api/[owner]/[repo]/[branch]/storage/multipart` with `action: create →
sign-parts → complete` (or `abort` on failure). Make sure your bucket allows
`AbortMultipartUpload` and consider an R2/S3 lifecycle rule that aborts
incomplete multipart uploads after 1 day.

## Rate limits

Token-bucket limits live in `lib/rate-limit.ts` and persist to the
`rate_limit` table. Per-user-per-repo defaults:

- `upload`: 60 requests / minute
- `upload-bytes`: 1 GB / hour
- `presign`: 120 requests / minute
- `delete`: 60 requests / minute

429 responses include a `Retry-After` hint. Override per-project by editing
`limitDefaults` in `lib/rate-limit.ts`.
