// @/db/envConfig is intentionally not imported here: it calls @next/env's
// loadEnvConfig(), which uses fs.statSync() — unsupported on Cloudflare
// Workers (unenv) and produces 4× errors per request. In the Worker,
// process.env is already populated from wrangler vars + secrets.
// drizzle.config.ts still imports it for local CLI use.
import { drizzle } from "drizzle-orm/postgres-js";
import postgres from "postgres";
import * as schema from './schema';

const client = postgres(process.env.DATABASE_URL!);
export const db = drizzle(client, { schema });