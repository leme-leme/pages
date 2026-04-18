import "@/db/envConfig";
import { defineConfig } from "drizzle-kit";

// SQLite (Cloudflare D1) — migrations are generated with drizzle-kit and
// applied against the remote D1 via `wrangler d1 migrations apply`.
// `dbCredentials` is only needed for drizzle-kit commands that talk to a
// local SQLite file (we don't use those here).
export default defineConfig({
  dialect: "sqlite",
  schema: "./db/schema.ts",
  out: "./db/migrations",
});
