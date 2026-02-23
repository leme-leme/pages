import * as schema from "./schema";
import { drizzle as drizzleD1 } from "drizzle-orm/d1";

let _db: ReturnType<typeof drizzleD1> | null = null;

export function getDb() {
  if (_db) return _db;

  // Cloudflare Pages: D1 binding via process.env (next-on-pages runtime)
  // The D1 binding is available as a global in the CF Workers runtime
  const binding = (process.env as any).DB || (globalThis as any).__env__?.DB;
  if (binding) {
    _db = drizzleD1(binding, { schema });
    return _db;
  }

  throw new Error("No D1 binding found. Ensure DB is bound in wrangler.toml");
}

// Backward-compatible proxy
export const db = new Proxy({} as any, {
  get(_, prop) {
    return (getDb() as any)[prop];
  },
});
