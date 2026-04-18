// D1-backed Drizzle client.
//
// The binding (env.DB) is only available during request handling on the
// Worker, so we resolve it lazily and cache within a request via react.cache.
// Callers continue to `import { db }` — the Proxy forwards every access to
// the per-request drizzle instance.
import { cache } from "react";
import { drizzle, type DrizzleD1Database } from "drizzle-orm/d1";
import { getCloudflareContext } from "@opennextjs/cloudflare";
import * as schema from "./schema";

type DB = DrizzleD1Database<typeof schema>;

const getDb = cache((): DB => {
	const { env } = getCloudflareContext();
	const d1 = (env as unknown as { DB: unknown }).DB;
	if (!d1) throw new Error("D1 binding `DB` is missing from the Worker env.");
	return drizzle(d1 as any, { schema });
});

export const db: DB = new Proxy({} as DB, {
	get(_target, prop) {
		const instance = getDb() as any;
		const value = instance[prop];
		return typeof value === "function" ? value.bind(instance) : value;
	}
});
