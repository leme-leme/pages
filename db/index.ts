import * as schema from "./schema";

let _db: any;

export function getDb() {
  if (_db) return _db;

  if (typeof process !== "undefined" && process.env.NODE_ENV === "development") {
    // Local dev: better-sqlite3
    const { drizzle } = require("drizzle-orm/better-sqlite3");
    const Database = require("better-sqlite3");
    const url = process.env.DATABASE_URL || "file:./local.db";
    const sqlite = new Database(url.replace("file:", ""));
    sqlite.pragma("journal_mode = WAL");
    _db = drizzle(sqlite, { schema });
  } else {
    // Cloudflare Pages: D1 binding
    const { drizzle } = require("drizzle-orm/d1");
    const { getRequestContext } = require("@cloudflare/next-on-pages");
    const { env } = getRequestContext();
    _db = drizzle(env.DB, { schema });
  }

  return _db;
}

// For backward compatibility - lazy getter
export const db = new Proxy({} as any, {
  get(_, prop) {
    return (getDb() as any)[prop];
  },
});
