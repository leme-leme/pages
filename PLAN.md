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
- ✅ Admin overview metrics (user/install/repo/cache-file counts) — `app/(main)/admin/page.tsx`.
- ✅ GitHub Actions run log mirrored in D1 — `action_run` table, surfaced via `app/api/[owner]/[repo]/[branch]/actions/route.ts`.
- ✅ Entry edit history (read from GitHub commit log) — `app/api/[owner]/[repo]/[branch]/entries/[path]/history/route.ts`.
- ✅ Local-only recent-repos tracker — `lib/tracker.ts` (localStorage, no telemetry).
- ✅ **First-party CMS event stream** — every `recordAuditEvent` call also writes to the Cloudflare **Analytics Engine** binding `AE` (dataset `pages_cms_events`). Schema in `lib/analytics/schema.ts` (`blob1..17`, `double1..4`); writer in `lib/analytics/collect.ts`. Counterscale-style.
- ✅ **Storage byte counters** — `cms.media.upload`, `cms.media.delete`, `cms.media.egress` events emit `bytes` so SUM(`double2`) gives stored/egressed totals per project.
- ✅ **Pluggable site-analytics injection (PRIORITY)** — per-project config in `project_analytics_config` table for GA4 / Plausible / Cloudflare Web Analytics. CRUD at `/api/[owner]/[repo]/[branch]/analytics/config`. The deployed site embeds `<script src="…/analytics/snippet.js">` and the worker serves a tiny runtime (`lib/analytics/site-snippet.ts`) that honors DNT/Sec-GPC, optionally shows a consent banner, and injects the configured providers.
- ✅ **Core Web Vitals reporting** — `components/web-vitals-reporter.tsx` (no npm dep, raw PerformanceObserver) sends LCP/INP/CLS/FCP/TTFB to `/api/_metrics/web-vitals`, which writes `cms.web-vital` events to AE. Honors DNT and Sec-GPC at the browser layer.
- ✅ **Server error tracking → AE** — `toErrorResponse` in `lib/api-error.ts` emits `cms.error` events for status >= 500 with route + status + truncated message.
- ✅ **Admin analytics page** — `/[owner]/[repo]/[branch]/analytics` shows event totals per type, byte in/out per day, 5xx errors, and Web Vitals p75. Backed by `lib/analytics/query.ts` (Cloudflare AE SQL API; requires `CF_ACCOUNT_ID` + `CF_ANALYTICS_API_TOKEN` env).
- ✅ **Daily rollups → D1** — `lib/analytics/rollup.ts` `rollupYesterday` queries AE for the previous UTC day and writes per-(owner, repo, type) totals into `analytics_rollup` for >90-day retention. Cron `0 2 * * *` in `worker/index.ts`.
- ✅ **Privacy controls** — `ANALYTICS_DISABLED=true` env disables every server-side write. The Web Vitals route + reporter both short-circuit on DNT/Sec-GPC. The site-snippet runtime supports `requireConsent` + `honorDnt` flags per project, with a vanilla-JS opt-in banner that stores its decision in `localStorage["pcms.consent"]`.

- ✅ **Sparkline + bar chart components** — `components/charts/sparkline.tsx` (Sparkline, BarChart, DayBars). No chart-lib dep.
- ✅ **Top contributors / entries / media** — `topActors`, `topResources("collection"|"media")` AE SQL aggregates surfaced as bar charts.
- ✅ **Realtime view** — `realtimeMinutes` query + `/analytics/realtime` endpoint, polled every 10s in the dashboard.
- ✅ **Geo + device breakdowns** — `topCountries` + `userAgentBuckets` (multiIf-based bot/mobile/desktop split) using existing `country` and `userAgent` blobs.
- ✅ **CSV export** — `?format=csv` on `/analytics/dashboard` returns a flat (section, key1, key2, key3, value) CSV.
- ✅ **Site-side custom event ingest** — `POST /api/[owner]/[repo]/[branch]/analytics/event` accepts `{name, value?, page?, metadata?}` from the deployed site (rate-limited per IP, DNT-aware, requires the project to have an analytics config row). Events stored under index `site.<name>`.
- ✅ **Build/deploy analytics from `action_run`** — `lib/analytics/deploys.ts` `deployStats` (success rate, mean, p95) + `deploysByDay` rendered as a stacked bar.

### Future hardening
- ⬜ Per-route latency p50/p95/p99 (need to capture `Server-Timing`-style request duration in the worker fetch handler).
- ⬜ Audit-event aggregates surfaced as content velocity / stale collections (use `analytics_rollup` over a 1-year window).
- ⬜ Sentry integration for client-side JS errors (server errors already go to AE).
- ⬜ Replace the inline Web Vitals reporter with the `web-vitals` npm package once we have a use case for INP attribution.

---

## Suggested sequencing

1. ✅ **Storage hardening first** — done. Presigned URLs, per-project config, lifecycle GC, reconciliation, signed reads, image variants, usage counters, rate limits, docs.
2. ✅ **Roles + audit log next** — done. Full role/grant model, branch scoping, delegated invites, audit log, non-GitHub identity, API tokens, permission UI.
3. ✅ **Analytics last** — done. AE binding wired, audit + storage + errors + Web Vitals + realtime all flow into `pages_cms_events`. Per-project site-analytics injection covers GA4/Plausible/CF Web Analytics with consent. Daily rollups extend retention beyond AE's 90-day window. Dashboard surfaces top contributors / entries / media / countries / UA buckets / deploy success rate, with CSV export and a public site-event ingest endpoint.
