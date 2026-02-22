import { drizzle } from "drizzle-orm/better-sqlite3";
import Database from "better-sqlite3";
import * as schema from "./schema";

// For local development: SQLite file
// For Cloudflare: D1 binding (see lib/d1.ts)
const url = process.env.DATABASE_URL || "file:./local.db";
const filePath = url.replace("file:", "");
const sqlite = new Database(filePath);
sqlite.pragma("journal_mode = WAL");

export const db = drizzle(sqlite, { schema });
