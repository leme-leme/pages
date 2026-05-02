# Roadmap: Storage, Permissions, Analytics

Status legend: ✅ shipped in fork · 🟡 partial · ⬜ not started

---

## 1. File storage — connect with AWS S3, Cloudflare R2, and more

### Shipped in our fork
- ✅ S3-compatible client with R2/MinIO support — `lib/storage/s3.ts` (custom endpoint, force path-style toggle).
- ✅ Hybrid upload routing — `app/api/[owner]/[repo]/[branch]/files/[path]/route.ts:186` routes media >25 MB to S3 and ≤25 MB to GitHub.
- ✅ Read-through public proxy — `app/api/s3/[...path]/route.ts` with `Cache-Control` headers.
- ✅ Delete handling — same files route at `:535` shortcuts S3-stored objects (commits `5e17606`, `8d8f0ef`).
- ✅ Replace-from-library for single-image fields (commit `44cc160`).
- ✅ D1 cache of every file's backend — `db/schema.ts` `cache_file_table` (`provider`, `s3_key`, `size`, `downloadUrl`).
- ✅ Per-deployment config via Worker env vars (`PAGES_S3_*`).
- ✅ Client-side upload UI with drag/drop + validation — `components/media/media-upload.tsx`.

### Needed for production
- ⬜ **Presigned PUT URLs** — direct browser→S3 uploads to bypass the Worker request size limit and cut bandwidth costs. Issue presigned URLs from a new `/api/s3/sign` route; finalize the DB row on a confirmation callback.
- ⬜ **Multipart uploads** — required for files >100 MB and to make large uploads resumable. AWS SDK `Upload` helper or manual `CreateMultipartUpload`/`UploadPart`/`CompleteMultipartUpload`.
- ⬜ **Per-project storage config in D1** — today bucket/credentials are global env vars; production needs per-site config (bucket, region, endpoint, credentials, prefix) stored encrypted in D1 and resolved at request time.
- ⬜ **Lifecycle / retention rules** — orphan media (rows in `cache_file_table` not referenced by any entry) accumulates forever. Add a scheduled Worker (Cron Trigger) that GCs unreferenced objects after N days.
- ⬜ **S3 → D1 reconciliation** — handle out-of-band changes (operator deletes from console). Either an S3 event → Queue → Worker pipeline, or a periodic `ListObjectsV2` reconcile job.
- ⬜ **Server-side image processing** — variants (thumbnail/medium/large), format conversion (HEIC→JPEG), and EXIF stripping. Run via Cloudflare Images binding or `wasm-vips`.
- ⬜ **Hard size + rate limits server-side** — current limits are client-side only (`config.extensions`). Enforce in the upload route and presign issuer.
- ⬜ **Bucket policy / CORS templates** — ship documented R2 + S3 setup snippets; today operators must figure it out.
- ⬜ **Signed read URLs for private buckets** — proxy currently assumes public objects. Add a private mode that mints short-lived GET URLs.
- ⬜ **Usage accounting** — track bytes stored / bytes egressed per project for billing or quota enforcement.

---

## 2. Permissions — granular access control for different content types

### Shipped in our fork
- ✅ GitHub-backed auth via Better Auth + D1 sessions — `lib/session-server.ts`, session expiry on GitHub token failure (commit `8778f16`).
- ✅ Repo write-access gate — `lib/authz-server.ts` `requireGithubRepoWriteAccess`, shared with client via `lib/authz-shared.ts`.
- ✅ Permission cache (60 min TTL) to avoid hammering GitHub — `lib/github-cache-permissions.ts`.
- ✅ Email-based collaborator invites with magic links — `lib/actions/collaborator.ts`, `db/schema.ts` `collaborator_table`.
- ✅ Schema-level operation toggles (create/rename/delete) per collection/file/settings scope — `lib/operations.ts`.

### Needed for production
- ⬜ **Role model** — at minimum `owner` / `editor` / `author` / `viewer`. Add `role` column to `collaborator_table`; default existing rows to `editor`.
- ⬜ **Collection-level grants** — restrict who can edit which content type. New `collaborator_grant` table: `(collaborator_id, scope_type, scope_value, permission)` where `scope_type ∈ {collection, file, media}`.
- ⬜ **Field-level visibility / editability** — extend the field schema with `permissions: { read?, write? }` keyed by role; enforce in the entry editor and on the server PUT route.
- ⬜ **Branch scoping** — `collaborator_table.branch` exists but is unused (`lib/actions/collaborator.ts:126` TODO). Wire it through invite flow and authz checks.
- ⬜ **Delegated invites** — let non-owner collaborators invite others within their grant scope (`lib/actions/collaborator.ts:119` TODO). Drop the requirement to be a GitHub repo admin.
- ⬜ **Audit log** — new `audit_event` table capturing `(actor, action, resource, before, after, ts)`. Write from the entry/media/settings mutation routes; expose in admin UI.
- ⬜ **Non-GitHub identity** — today every user must have a GitHub account. Add email/password or OIDC so collaborators on private content don't need GitHub.
- ⬜ **Decouple authz from GitHub permission cache** — once roles are stored locally, the GitHub permission cache becomes a fallback rather than the source of truth. Define precedence clearly.
- ⬜ **API tokens** — scoped PATs for headless usage (CI deploys, external editors). Store hashed in D1, scoped to roles + collections.
- ⬜ **Permission UI** — settings page to manage roles, grants, and field-level rules without editing config files.

---

## 3. Analytics — integrate with GA, Cloudflare Analytics, and more

### Shipped in our fork
- 🟡 Admin overview metrics (user/install/repo/cache-file counts) — `app/(main)/admin/page.tsx`.
- 🟡 GitHub Actions run log mirrored in D1 — `db/schema.ts` `action_run`, surfaced via `app/api/[owner]/[repo]/[branch]/actions/route.ts`.
- 🟡 Entry edit history (read from GitHub commit log) — `app/api/[owner]/[repo]/[branch]/entries/[path]/history/route.ts`.
- 🟡 Local-only recent-repos tracker — `lib/tracker.ts` (localStorage, no telemetry).
- ⬜ No third-party analytics, no Web Vitals, no error tracking wired in.

### Needed for production
- ⬜ **Pluggable site-analytics injection** — per-project config that injects GA4 / Plausible / Cloudflare Web Analytics tags into the *deployed* site. Options stored in the repo's `.pages.yml` or D1 site config; rendered in the build output.
- ⬜ **CMS product analytics** — first-party event stream for the CMS itself (entry created/edited/published, media uploaded, login). Cloudflare Analytics Engine binding is the natural fit (cheap, already on the Worker runtime).
- ⬜ **Core Web Vitals reporting** — wire the `web-vitals` package in `app/layout.tsx`; ship metrics to Analytics Engine or GA4.
- ⬜ **Error tracking** — Sentry (or Cloudflare's built-in Workers Logs / Tail Workers) for server + client errors; today errors go to console only.
- ⬜ **Audit-event analytics** — once the audit log from §2 lands, surface aggregates: edits per user, content velocity, stale collections.
- ⬜ **Storage usage dashboards** — bytes stored / egressed per project, top files, growth curves. Backed by the usage accounting in §1.
- ⬜ **Build/deploy analytics** — surface Workers/Pages deploy success rate, duration, and queue depth alongside the existing `action_run` data.
- ⬜ **Admin analytics page** — replace the four-number admin overview with time-series charts (DAU, uploads/day, errors/day) sourced from Analytics Engine.
- ⬜ **Privacy / cookie controls** — consent banner + DNT honoring before any third-party tag fires; GDPR-friendly defaults.
- ⬜ **Documented opt-out** — env flag to disable all telemetry for self-hosters.

---

## Suggested sequencing

1. **Storage hardening first** (presigned URLs, per-project config, lifecycle GC) — unblocks paying users with real media volumes.
2. **Roles + audit log next** — needed before any multi-tenant rollout; the audit log doubles as the data source for §3.
3. **Analytics last** — built on top of the audit + usage data the previous two phases produce, so it isn't a separate instrumentation pass.
