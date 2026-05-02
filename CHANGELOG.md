# Changelog (fork)

All changes in this repo on top of upstream
[`pagescms/pagescms@2.1.6`](https://github.com/pagescms/pagescms/tree/69d0215)
(merge base `69d0215`).

Status: deployed to https://pages-cms.leme.workers.dev (Cloudflare Worker
`pages-cms`, D1 `pages-cms-vinext-db`, AE dataset `pages_cms_events`).

---

## Platform — Cloudflare Workers + D1 + vinext

The fork is no longer a stock Next.js app on Vercel/Node + libsql; it runs as
a single Cloudflare Worker with D1 as the database, served through the
[`vinext`](https://www.npmjs.com/package/vinext) build of Next.js.

- `d188d2f` **vinext + D1 wiring** on top of the 2.1.6 base.
- `0363f63`, `182dfa9`, `5c99459` **Drizzle dialect → sqlite/D1**, Better
  Auth drizzle adapter told it's on sqlite/D1, build pipeline cleaned up.
- `3a977bc` **Single sqlite migration baseline** — upstream's 12 historical
  migrations rebased into one (`0000_bored_captain_america.sql`); subsequent
  migrations are this fork's only.
- `144d5ba`, `ca152d9` `better-auth/next-js` `nextCookies` plugin dropped;
  `request.nextUrl` swapped for `new URL(request.url)` for vinext compat.
- `45bfcaa`, `ee449a6`, `f1f4e0c`, `2f655fa` D1 binding ID, `wrangler.jsonc`
  service name, `.npmrc` legacy-peer-deps, deploy ownership of schema.
- `9031381` D1 ~100-parameter limit handled by chunked `cache_file` inserts.
- `17bea61` `upload_source_maps` enabled for unminified worker stack traces.
- `43da4bc` GitHub Actions deploy workflow + `wrangler.jsonc` service name.
- `55fb297`, `f52d34f` zod 3.25 → 4.4 migration for Better Auth compat.

Files: `wrangler.jsonc`, `worker/index.ts`, `vite.config.ts`,
`cloudflare-env.d.ts`, `db/index.ts`, `db/migrations/000{0,1}_*.sql`,
`.github/workflows/deploy.yml`, `.npmrc`.

---

## Storage — S3 / R2 backend

Hybrid storage: GitHub for small text files, S3-compatible bucket for
everything else. Per-project config, presigned uploads, multipart, lifecycle
GC, S3 ↔ D1 reconciliation, image variants, signed reads, usage accounting.

### Backend
- `lib/storage/s3.ts` — S3-compatible client (R2/MinIO/AWS), `getStorageConfig`
  resolver (D1 → env fallback), helpers for presigned PUT, multipart
  create/sign-parts/complete/abort, presigned GET, list. `5e17606`.
- `db/schema.ts` `cache_file` — `provider` ("github"|"s3"), `s3_key`,
  `referenced_at` (for orphan GC).
- `db/schema.ts` `project_storage_config` — encrypted creds via
  `lib/crypto.ts`, per-project `endpoint`/`bucket`/`prefix`/`visibility`/
  `thresholdBytes`/`maxFileBytes`/`publicBaseUrl`. `99f463e`.
- `db/schema.ts` `storage_usage` — bytes-stored / bytes-egressed /
  file-count per (owner, repo, branch). `lib/storage/usage.ts`.
- `db/schema.ts` `rate_limit` — token-bucket state. `lib/rate-limit.ts`
  covers `upload`, `upload-bytes`, `presign`, `delete`.

### Routes
- `app/api/[owner]/[repo]/[branch]/files/[path]/route.ts` — POST routes
  media >threshold to S3, ≤threshold to GitHub; DELETE shortcuts S3-stored
  objects; audit + usage + rate-limit + permission gate. `5e17606`,
  `8d8f0ef`, `99f463e`.
- `app/api/[owner]/[repo]/[branch]/storage/presign/route.ts` — presigned PUT
  URLs; browser uploads ≥25 MB skip the worker.
- `app/api/[owner]/[repo]/[branch]/storage/finalize/route.ts` — writes the
  cache row + usage counter + audit event after a presigned PUT or
  multipart complete; spawns image-variant generation.
- `app/api/[owner]/[repo]/[branch]/storage/multipart/route.ts` — `create /
  sign-parts / complete / abort` for files ≥100 MB.
- `app/api/[owner]/[repo]/[branch]/storage/config/route.ts` — GET / PUT /
  DELETE per-project storage config with admin permission check.
- `app/api/s3/[...path]/route.ts` — public proxy with `Cache-Control`;
  private buckets gated by `resolveRepoAccess` and 302→presigned GET.
- `app/api/[owner]/[repo]/[branch]/files-batch/route.ts` — batched file
  writes for collection reordering.

### Background jobs
- `lib/storage/lifecycle.ts` `gcOrphanMedia` — daily cron `0 3 * * *`
  deletes S3-backed cache rows whose `referenced_at` and `updated_at` are
  both older than `STORAGE_ORPHAN_AGE_DAYS` (default 30); writes audit
  event.
- `lib/storage/lifecycle.ts` `reconcileBucketWithCache` +
  `pickReconcileTargets` — every 30 min walks `ListObjectsV2` per project,
  drops cache rows whose objects are gone.
- `lib/storage/image-processing.ts` — `thumb` (240w) / `medium` (1024w) /
  `large` (2048w) WebP variants via the Cloudflare `IMAGES` binding.

### UI
- `components/media/media-upload.tsx` — drag/drop, client-side raster
  optimization (`f9a504b`), auto-routes ≥25 MB through presign and ≥100 MB
  through resumable multipart with abort-on-failure.
- `components/media/media-lightbox.tsx`, `components/thumbnail.tsx` — image
  lightbox + video thumbnails (`c2190ca`, `5c735b2`).

---

## Permissions & auth — RBAC

Upstream had GitHub-OAuth-only auth and a binary "invited or not" model. The
fork adds a full role/grant model, branch scoping, audit log, non-GitHub
identity, API tokens.

### Roles, grants, and authz
- `db/schema.ts` `collaborator.role` — `owner | editor | author | viewer`;
  existing rows defaulted to `editor` in migration `0002`.
- `db/schema.ts` `collaborator_grant` — `(collaborator_id, scope_type,
  scope_value, permission)`, `scope_type ∈ {collection, file, media}`,
  `permission ∈ {read, write, publish, admin}`.
- `lib/permissions.ts` — `Role`, `ScopeType`, `Permission`,
  `hasPermission`, `canManageCollaborators`, `ROLE_RANKS`.
- `lib/authz-server.ts` `resolveRepoAccess` — precedence GitHub admin →
  GitHub write → local D1 collaborator/grants → none. The 60-min GitHub
  permission cache is a hint, not source of truth.
- `lib/field-permissions.ts` `stripUnwritableFields` runs in the entry POST
  before zod validation; `filterReadableFields` ready for editor wiring.
  Field schema accepts `permissions: { read?, write? }` keyed by role.
- `lib/actions/collaborator.ts` — invite gains role + branch + grants;
  delegated invites work for non-owner admins (`resolveInviteContext`
  reuses installation context from a sibling collaborator row); branch
  scoping honoured in invite and gate.

### Identity
- `lib/auth.ts` `emailAndPassword` Better Auth provider on (toggle via
  `AUTH_EMAIL_PASSWORD_ENABLED=false`); credential accounts trusted for
  linking.

### API tokens
- `db/schema.ts` `api_token` — sha256-hashed PATs prefixed `pcms_`,
  optional scope-to-(owner, repo, branch), per-token role + grants list,
  expiry, `last_used_at`.
- `lib/api-tokens.ts` — `generateApiToken`, `lookupApiTokenByRaw`,
  `createApiToken`, `revokeApiToken`.
- `lib/session-server.ts` — `Authorization: Bearer pcms_…` accepted on
  every API route.
- `app/api/me/tokens/route.ts` — CRUD.

### Audit log
- `db/schema.ts` `audit_event` — `(actor, action, resource, before, after,
  metadata, ts)`.
- `lib/audit.ts` `recordAuditEvent` — writes from media/content
  create/update/delete, collaborator add/remove/role/grants, storage
  config, API token CRUD; mirrors every event into Analytics Engine.
- `app/api/[owner]/[repo]/[branch]/audit/route.ts` — admin-only `GET` with
  filters.

### UI
- `components/collaborators.tsx` — invite dialog now collects role + branch
  + grants; per-row dropdown updates role and edits grants.

---

## Analytics — Cloudflare Analytics Engine + site-tag injection

First-party event stream for the CMS itself (Cloudflare Analytics Engine),
plus a per-project site-analytics injection (GA4 / Plausible / CF Web
Analytics) for the deployed site.

### Pipeline
- `wrangler.jsonc` `analytics_engine_datasets` binding `AE` (dataset
  `pages_cms_events`).
- `lib/analytics/schema.ts` — `blob1..17` / `double1..4` column mapping;
  EventType taxonomy (`cms.entry.*`, `cms.media.*`, `cms.collaborator.*`,
  `cms.api-token.*`, `cms.storage-config.*`, `cms.session.start`,
  `cms.error`, `cms.web-vital`).
- `lib/analytics/collect.ts` `writeEvent` — writes to `env.AE`, truncates
  blobs, no-ops when `ANALYTICS_DISABLED=true` or AE binding absent.
- `lib/analytics/query.ts` — Cloudflare AE SQL API client;
  `eventsByDay`, `topActors`, `errorsByDay`, `webVitalsByDay`,
  `storageBytesByDay`. Requires `CF_ACCOUNT_ID` +
  `CF_ANALYTICS_API_TOKEN`.
- `lib/analytics/rollup.ts` — daily cron `0 2 * * *` writes per-day
  aggregates into `analytics_rollup` for >90-day retention.

### Routes
- `app/api/[owner]/[repo]/[branch]/analytics/config/route.ts` —
  per-project GA4/Plausible/CF Web Analytics config CRUD (admin-only).
- `app/api/[owner]/[repo]/[branch]/analytics/snippet.js/route.ts` — public
  JS endpoint the deployed site embeds via
  `<script src="…/snippet.js">`. Honors DNT/Sec-GPC, optional consent
  banner with `localStorage["pcms.consent"]`, injects whichever providers
  are configured.
- `app/api/[owner]/[repo]/[branch]/analytics/dashboard/route.ts` —
  consolidates events / errors / storage / web vitals.
- `app/api/_metrics/web-vitals/route.ts` — `POST` from
  `components/web-vitals-reporter.tsx` (raw `PerformanceObserver`-based,
  no npm dep).

### UI
- `app/(main)/[owner]/[repo]/[branch]/analytics/page.tsx` — admin
  dashboard. Activity totals per type, byte-in/out per day, 5xx errors
  table, Web Vitals p75 by metric/day, snippet install instructions,
  site-config form.
- `components/web-vitals-reporter.tsx` — `PerformanceObserver` for
  LCP/INP-proxy/CLS/FCP/TTFB; reports via `navigator.sendBeacon`.

### Privacy
- `ANALYTICS_DISABLED=true` env disables every server-side AE write.
- Web Vitals route + reporter both short-circuit on DNT / Sec-GPC.
- Site-snippet runtime supports `requireConsent` + `honorDnt` flags
  per project; injects providers only after user opts in.

### Server error tracking
- `lib/api-error.ts` `toErrorResponse` emits `cms.error` AE events for
  status ≥ 500 with route + status + truncated message.

---

## i18n

- `c547e68`, `53cbbef`, `bfe359d` — `LocaleProvider` mounted in entry
  editor, `i18n` field type, locale-aware `multiple_files` /
  `multiple_folders` routing.
- Files: `contexts/locale-context.tsx`, `lib/i18n.ts`,
  `components/locale-switcher.tsx`, `fields/core/i18n/`.

---

## Editor & media UX

- `a7e944a` Drag-and-drop reorder in collection table view.
- `25bcbb2` Video hover-scrub, arrow-key media navigation, Blacksmith CI,
  comment cleanup.
- `1f76fee` Reference field — server-side pagination + infinite scroll.
- `5c735b2`, `c2190ca`, `f9a504b`, `2d73873` Gallery layout for image
  fields, image lightbox, client-side raster optimization on upload, Apple
  touch icon + `web-app-capable` meta.
- `44cc160` Replace-from-library button for single-image fields.
- `ee285dc` Gallery layout for collections + drag-and-drop frontmatter
  reorder.
- `889178a`, `249466a` Repo-layout error labelling, direct
  `@radix-ui/react-slot` import in server components.

Files include `components/collection/collection-gallery.tsx`,
`components/media/media-lightbox.tsx`, `components/locale-switcher.tsx`,
plus modifications to `components/collection/collection.tsx`,
`components/entry/entry.tsx`, `components/media/media-view.tsx`,
`fields/core/{file,image,reference,select}/*`, `fields/registry.ts`.

---

## DB migrations

Upstream's 12 historical migrations were rebased into a single sqlite
baseline (`0000_bored_captain_america.sql`). The fork adds:

- `0001_brainy_ultron.sql` — `cache_file.provider` + `cache_file.s3_key`.
- `0002_unknown_lifeguard.sql` — `project_storage_config`, `audit_event`,
  `api_token`, `storage_usage`, `rate_limit`, `collaborator_grant`,
  `collaborator.role`, `cache_file.referenced_at`.
- `0003_absent_wasp.sql` — `project_analytics_config`, `analytics_rollup`.

---

## Cron triggers

| Cron | Job | File |
| --- | --- | --- |
| `0 2 * * *` | Analytics rollup → `analytics_rollup` | `lib/analytics/rollup.ts` |
| `0 3 * * *` | Orphan media GC | `lib/storage/lifecycle.ts` |
| `*/30 * * * *` | S3 ↔ D1 reconciliation | `lib/storage/lifecycle.ts` |

---

## Env vars

Required to enable the new flows. None of these are secrets to upstream
pagescms because they describe fork-only features.

| Var | Purpose |
| --- | --- |
| `CRYPTO_KEY` | AES-GCM key for encrypting per-project S3 creds in D1. |
| `PAGES_S3_*` | Fallback storage config when no D1 row matches. |
| `STORAGE_ORPHAN_AGE_DAYS` | Orphan GC threshold (default 30). |
| `CF_ACCOUNT_ID` / `CF_ANALYTICS_API_TOKEN` | Enables AE SQL queries. |
| `AE_DATASET` | AE dataset name (default `pages_cms_events`). |
| `ANALYTICS_DISABLED` | Disables all AE writes when `=true`. |
| `AUTH_EMAIL_PASSWORD_ENABLED` | `false` to disable email/password sign-in. |
| `COLLABORATOR_INVITE_LINK_EXPIRES_IN` | Invite magic-link TTL seconds (default 86400). |
