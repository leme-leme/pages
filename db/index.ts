import * as schema from "./schema";
import { drizzle as drizzleD1 } from "drizzle-orm/d1";
import { getRequestContext } from "@cloudflare/next-on-pages";

export function getDb() {
  const { env } = getRequestContext();
  const binding = (env as any).DB;
  if (!binding) {
    throw new Error("No D1 binding found. Ensure DB is bound in wrangler.toml");
  }
  return drizzleD1(binding, { schema });
}

// Backward-compatible proxy
export const db = new Proxy({} as any, {
  get(_, prop) {
    return (getDb() as any)[prop];
  },
});
