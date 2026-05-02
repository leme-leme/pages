import "server-only";

import { db } from "@/db";
import { apiTokenTable, userTable } from "@/db/schema";
import { and, eq, gt, isNull, or, sql } from "drizzle-orm";
import { randomBytes } from "crypto";
import type { Role } from "@/lib/permissions";

const TOKEN_PREFIX = "pcms_";

const sha256Hex = async (input: string): Promise<string> => {
  const data = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
};

export async function generateApiToken(): Promise<{ raw: string; prefix: string; hash: string }> {
  const bytes = randomBytes(32).toString("base64url");
  const raw = `${TOKEN_PREFIX}${bytes}`;
  const prefix = raw.slice(0, 12);
  const hash = await sha256Hex(raw);
  return { raw, prefix, hash };
}

export async function lookupApiTokenByRaw(raw: string) {
  if (!raw.startsWith(TOKEN_PREFIX)) return null;
  const hash = await sha256Hex(raw);
  const row = await db.query.apiTokenTable.findFirst({
    where: and(
      eq(apiTokenTable.hash, hash),
      isNull(apiTokenTable.revokedAt),
      or(isNull(apiTokenTable.expiresAt), gt(apiTokenTable.expiresAt, new Date())),
    ),
  });
  if (!row) return null;
  await db.update(apiTokenTable)
    .set({ lastUsedAt: new Date() })
    .where(eq(apiTokenTable.id, row.id));
  return row;
}

export type ParsedTokenScopes = { scopeType: "collection" | "file" | "media"; scopeValue: string; permission: "read" | "write" | "publish" | "admin" }[];

export function parseScopes(value: string | null | undefined): ParsedTokenScopes {
  if (!value) return [];
  try {
    const parsed = JSON.parse(value);
    if (!Array.isArray(parsed)) return [];
    return parsed.filter((g) =>
      g && typeof g === "object" &&
      ["collection", "file", "media"].includes(g.scopeType) &&
      typeof g.scopeValue === "string" &&
      ["read", "write", "publish", "admin"].includes(g.permission)
    );
  } catch {
    return [];
  }
}

export async function createApiToken(opts: {
  userId: string;
  name: string;
  owner?: string;
  repo?: string;
  branch?: string;
  role?: Role;
  scopes?: ParsedTokenScopes;
  expiresAt?: Date;
}): Promise<{ id: number; raw: string; prefix: string; expiresAt: Date | null }> {
  const { raw, prefix, hash } = await generateApiToken();
  const inserted = await db.insert(apiTokenTable).values({
    userId: opts.userId,
    name: opts.name,
    prefix,
    hash,
    owner: opts.owner ?? null,
    repo: opts.repo ?? null,
    branch: opts.branch ?? null,
    role: opts.role ?? "editor",
    scopes: JSON.stringify(opts.scopes ?? []),
    expiresAt: opts.expiresAt ?? null,
  }).returning();
  return { id: inserted[0].id, raw, prefix, expiresAt: inserted[0].expiresAt };
}

export async function listApiTokens(userId: string) {
  return db.query.apiTokenTable.findMany({
    where: eq(apiTokenTable.userId, userId),
    orderBy: (t, { desc }) => [desc(t.createdAt)],
  });
}

export async function revokeApiToken(userId: string, id: number) {
  await db.update(apiTokenTable)
    .set({ revokedAt: new Date() })
    .where(and(eq(apiTokenTable.id, id), eq(apiTokenTable.userId, userId)));
}

export async function getUserForToken(token: typeof apiTokenTable.$inferSelect) {
  return db.query.userTable.findFirst({ where: eq(userTable.id, token.userId) });
}

// Suppress unused
void sql;
