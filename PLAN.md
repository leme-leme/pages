# Roadmap: Storage, Permissions, Analytics

Status legend: ✅ shipped in fork · 🟡 partial · ⬜ not started

---

## 1. File storage — connect with AWS S3, Cloudflare R2, and more

### Shipped in our fork
- ✅ S3-compatible client with R2/MinIO support — `lib/storage/s3.ts` (custom endpoint, force path-style toggle).
- ✅ Hybrid upload routing — `app/api/[owner]/[repo]/[branch]/files/[path]/route.ts` routes media >threshold to S3 and ≤threshold to GitHub.
- ✅ Read-through public proxy — `app/api/s3/[...path]/route.ts` with `Cache-Control` headers + `referenced_at` touch for GC.
- ✅ Delete handling — same files route shortcuts S3-stored objects (commits `5e17606`, `8d8f0ef`).
- ✅ Replace-from-library for single-image fields (commit `44cc160`).
- ✅ D1 cache of every file's backend — `db/schema.ts` `cache_file_table` (`provider`, `s3_key`, `size`, `download_url`, `referenced_at`).
- ✅ Per-deployment fallback config via Worker env vars (`PAGES_S3_*`).
- ✅ Client-side upload UI with drag/drop + validation — `components/media/media-upload.tsx`.
- ✅ **Presigned PUT URLs** — `app/api/[owner]/[repo]/[branch]/storage/presign/route.ts` issues short-lived PUT URLs; `storage/finalize` writes the cache row + usage counter + audit event. Browser uploads ≥25 MB skip the worker.
- ✅ **Multipart uploads** — `storage/multipart/route.ts` handles `create / sign-parts / complete / abort`. Client driver in `media-upload.tsx` chunks ≥100 MB into 8 MB parts and aborts on failure.
- ✅ **Per-project storage config in D1** — `project_storage_config` table (encrypted creds via `lib/crypto.ts`); resolver in `lib/storage/s3.ts` `getStorageConfig` (D1 → env fallback). CRUD at `storage/config/route.ts` (GET/PUT/DELETE).
- ✅ **Lifecycle / orphan media GC** — `lib/storage/lifecycle.ts` `gcOrphanMedia` deletes S3-backed cache rows whose `referenced_at` and `updated_at` are both older than `STORAGE_ORPHAN_AGE_DAYS` (default 30). Daily Cron Trigger (`0 3 * * *`) in `worker/index.ts`.
- ✅ **S3 → D1 reconciliation** — `reconcileBucketWithCache` walks `ListObjectsV2` per `(owner, repo, branch)` and drops cache rows whose objects are gone. 30-min Cron Trigger (`*/30 * * * *`).
- ✅ **Server-side image processing** — `lib/storage/image-processing.ts` generates `thumb/medium/large` WebP variants via the Cloudflare `IMAGES` binding; runs best-effort from `storage/finalize` and counts toward `storage_usage`.
- ✅ **Hard size + rate limits server-side** — `maxFileBytes` enforced in upload + presign + multipart routes (413 on over-cap). Token-bucket rate limiter in `lib/rate-limit.ts` (D1-backed) covers `upload`, `upload-bytes`, `presign`, `delete`.
- ✅ **Bucket policy / CORS templates** — `docs/storage-setup.md` with R2 + S3 IAM policies, CORS JSON (incl. `ExposeHeaders: [ETag]` for multipart), and lifecycle/cron docs.
- ✅ **Signed read URLs for private buckets** — `s3PublicUrl` honours `visibility=private`; the `/api/s3/[...path]` proxy gates by `resolveRepoAccess` + `hasPermission(read, media)` and 302s to `s3PresignedGet`.
- ✅ **Storage usage accounting** — `storage_usage` table updated on upload (positive), delete (negative), GC (negative), egress (proxy + private). `lib/storage/usage.ts` `recordUsage` / `getUsage`.

### Future hardening
- ⬜ S3 event-bus webhooks instead of polling reconcile (lower latency on out-of-band changes).
- ⬜ HEIC → JPEG conversion + format negotiation on read.
- ⬜ Per-project rate-limit overrides (current limits are global defaults in `lib/rate-limit.ts`).

---

## 2. Permissions — granular access control for different content types

### Shipped in our fork
- ✅ GitHub-backed auth via Better Auth + D1 sessions — `lib/session-server.ts`, session expiry on GitHub token failure (commit `8778f16`).
- ✅ Repo write-access gate — `lib/authz-server.ts` `requireGithubRepoWriteAccess`, shared with client via `lib/authz-shared.ts`.
- ✅ Permission cache (60 min TTL) to avoid hammering GitHub — `lib/github-cache-permissions.ts`.
- ✅ Email-based collaborator invites with magic links — `lib/actions/collaborator.ts`, `db/schema.ts` `collaborator_table`.
- ✅ Schema-level operation toggles (create/rename/delete) per collection/file/settings scope — `lib/operations.ts`.
- ✅ **Role model** — `collaborator.role` column (`owner | editor | author | viewer`). `lib/permissions.ts` defines `ROLE_RANKS` + role-default permissions; existing rows defaulted to `editor` in migration `0002`.
- ✅ **Collection-level grants** — `collaborator_grant` table `(collaborator_id, scope_type, scope_value, permission)` with `scope_type ∈ {collection, file, media}`. `hasPermission` consults grants before falling back to role baseline.
- ✅ **Field-level visibility / editability** — `lib/field-permissions.ts` `stripUnwritableFields` runs in the entry POST before zod validation; `filterReadableFields` available for editors. Field schema accepts `permissions: { read?, write? }` keyed by role.
- ✅ **Branch scoping** — `collaborator.branch` is wired through invite flow, `resolveAccessForUser`, and `requirePermission(... branch)`. Empty/`*` = all branches.
- ✅ **Delegated invites** — non-owner admins can invite within their scope (`lib/actions/collaborator.ts` `resolveInviteContext`). Owner branch retains the GitHub-installation context for new repos.
- ✅ **Audit log** — `audit_event` table; writes from media/content create/update/delete, collaborator add/remove/role/grants, storage config + API token CRUD. Surfaced via `GET /api/[owner]/[repo]/[branch]/audit` (admin-only).
- ✅ **Non-GitHub identity** — Better Auth `emailAndPassword` provider enabled (toggle via `AUTH_EMAIL_PASSWORD_ENABLED=false`); credential accounts are trusted for linking.
- ✅ **Decouple authz from GitHub permission cache** — `resolveRepoAccess` enforces precedence: GitHub admin → GitHub write → local D1 collaborator/grants → none. The GitHub permission cache is now a hint, not the source of truth.
- ✅ **API tokens** — `api_token` table stores sha256-hashed PATs (prefix `pcms_`). `Authorization: Bearer …` accepted on every API route via `requireApiUserSession`. CRUD at `/api/me/tokens`.
- ✅ **Permission UI** — invite dialog in `components/collaborators.tsx` collects role + branch + grants; per-row dropdown updates role and edits grants (JSON editor).

### Future hardening
- ⬜ Inline grants editor with autocomplete from `.pages.yml` instead of raw JSON prompt.
- ⬜ Per-token scope refinement and "last used IP" surfacing in the UI.
- ⬜ OIDC / SAML for enterprise tenants.
- ⬜ Audit-log filtering UI (currently API-only; admin must build their own viewer or curl).

---

## 3. Analytics — integrate with GA, Cloudflare Analytics, and more

### Shipped in our fork
- 🟡 Admin overview metrics (user/install/repo/cache-file counts) — `app/(main)/admin/page.tsx`.
- 🟡 GitHub Actions run log mirrored in D1 — `db/schema.ts` `action_run`, surfaced via `app/api/[owner]/[repo]/[branch]/actions/route.ts`.
- 🟡 Entry edit history (read from GitHub commit log) — `app/api/[owner]/[repo]/[branch]/entries/[path]/history/route.ts`.
- 🟡 Local-only recent-repos tracker — `lib/tracker.ts` (localStorage, no telemetry).
- 🟡 First-party event stream available via the new `audit_event` table from §2 (mutation log; not yet surfaced as charts).
- 🟡 Storage byte counters available via `storage_usage` from §1 (per-project; not yet surfaced as charts).
- ⬜ No third-party analytics, no Web Vitals, no error tracking wired in.

### Needed for production
- ⬜ **Pluggable site-analytics injection** — per-project config that injects GA4 / Plausible / Cloudflare Web Analytics tags into the *deployed* site. Options stored in the repo's `.pages.yml` or D1 site config; rendered in the build output.
- ⬜ **CMS product analytics** — first-party event stream for the CMS itself. The audit log already captures mutations; pipe a sampled subset to Cloudflare Analytics Engine for cheap aggregation.
- ⬜ **Core Web Vitals reporting** — wire the `web-vitals` package in `app/layout.tsx`; ship metrics to Analytics Engine or GA4.
- ⬜ **Error tracking** — Sentry (or Cloudflare's built-in Workers Logs / Tail Workers) for server + client errors; today errors go to console only.
- ⬜ **Audit-event analytics** — aggregate `audit_event` rows to surface edits per user, content velocity, stale collections.
- ⬜ **Storage usage dashboards** — render `storage_usage` as bytes-stored / bytes-egressed time series; surface top files + growth curves.
- ⬜ **Build/deploy analytics** — surface Workers/Pages deploy success rate, duration, and queue depth alongside the existing `action_run` data.
- ⬜ **Admin analytics page** — replace the four-number admin overview with time-series charts (DAU, uploads/day, errors/day) sourced from Analytics Engine + `audit_event` + `storage_usage`.
- ⬜ **Privacy / cookie controls** — consent banner + DNT honoring before any third-party tag fires; GDPR-friendly defaults.
- ⬜ **Documented opt-out** — env flag to disable all telemetry for self-hosters.

---

## Suggested sequencing

1. ✅ **Storage hardening first** — done. Presigned URLs, per-project config, lifecycle GC, reconciliation, signed reads, image variants, usage counters, rate limits, docs.
2. ✅ **Roles + audit log next** — done. Full role/grant model, branch scoping, delegated invites, audit log, non-GitHub identity, API tokens, permission UI.
3. ⬜ **Analytics last** — sits on top of the `audit_event` and `storage_usage` data the previous two phases produce. Pick an analytics destination (Cloudflare Analytics Engine for first-party + Plausible/GA4 for site-side) and wire dashboards.
