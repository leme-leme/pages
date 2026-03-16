# Changelog

## 2026-02-23 — Cloudflare Workers deployment fixes

### Auth adapter: PostgreSQL → SQLite
- `lib/auth.ts` used `DrizzlePostgreSQLAdapter` but the database is Cloudflare D1 (SQLite)
- Changed to `DrizzleSQLiteAdapter` to match the actual database dialect
- Without this fix, any Lucia session creation/validation fails at runtime

### Lazy initialization for Workers secrets
- `lib/auth.ts` line 49 created `new GitHub(clientId, clientSecret)` at **module load time**
- In Cloudflare Workers, secrets (set via `wrangler secret put`) are only available during request handling, not at module initialization
- Wrapped in a lazy proxy so the GitHub client is only instantiated on first use during a request

### GitHub OAuth token exchange: bypass Cloudflare WAF
- The `oslo/oauth2` library (used by `arctic`) sends `User-Agent: oslo` and `Content-Type: application/x-www-form-urlencoded` when exchanging the OAuth code for a token
- Cloudflare WAF blocks this request with "Request forbidden by administrative rules"
- Replaced with a direct `fetch` to `https://github.com/login/oauth/access_token` using `Content-Type: application/json` which is not blocked

### D1 database schema migration
- The D1 database had an old schema (`user` table with `id`, `username`, `name`, `avatar_url`)
- The code expects the new schema (`id`, `github_email`, `github_name`, `github_id`, `github_username`, `email`)
- Dropped all old tables and applied the correct migration from `db/migrations/0000_even_flatman.sql`

### Secrets management
- Removed secrets (`PAGES_DB_PASSWORD`, `PAGESCMS_CRYPTO_KEY`) from `wrangler.toml` — these were not used by the code
- Non-secret config vars (`BASE_URL`, `GITHUB_APP_ID`, `GITHUB_APP_NAME`, `GITHUB_APP_CLIENT_ID`) remain in `[vars]`
- Secrets are now managed via `wrangler secret put`:
  - `CRYPTO_KEY` — AES-GCM encryption key (code reads `process.env.CRYPTO_KEY`)
  - `GITHUB_APP_CLIENT_SECRET`
  - `GITHUB_APP_PRIVATE_KEY`
  - `GITHUB_APP_WEBHOOK_SECRET`
  - `CRON_SECRET`
  - `RESEND_API_KEY`
- Created `.dev.vars` for local development secrets (added to `.gitignore`)

### wrangler.toml fix
- Moved `routes` to top-level scope — it was incorrectly nested under `[assets]` which caused a wrangler warning
