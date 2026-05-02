import "server-only";

import { db } from "@/db";
import { collaboratorTable, collaboratorGrantTable } from "@/db/schema";
import { and, eq, sql } from "drizzle-orm";
import { collaboratorMatchesUserForRepo } from "@/lib/collaborator-access";
import type { User } from "@/types/user";

export type Role = "owner" | "editor" | "author" | "viewer";
export type ScopeType = "collection" | "file" | "media";
export type Permission = "read" | "write" | "publish" | "admin";

export const ROLE_RANKS: Record<Role, number> = {
  viewer: 1,
  author: 2,
  editor: 3,
  owner: 4,
};

const ROLE_DEFAULT_PERMS: Record<Role, Permission[]> = {
  viewer: ["read"],
  author: ["read", "write"],
  editor: ["read", "write", "publish"],
  owner: ["read", "write", "publish", "admin"],
};

export type ResolvedAccess = {
  role: Role;
  source: "github-owner" | "github-write" | "collaborator" | "api-token" | "none";
  branch?: string | null;
  collaboratorId?: number;
  // Per-scope grants. Empty = role-default applies everywhere.
  grants: { scopeType: ScopeType; scopeValue: string; permission: Permission }[];
};

export const NO_ACCESS: ResolvedAccess = {
  role: "viewer",
  source: "none",
  grants: [],
};

const isRole = (value: unknown): value is Role =>
  value === "owner" || value === "editor" || value === "author" || value === "viewer";

export async function resolveAccessForUser(
  user: Pick<User, "id" | "email">,
  owner: string,
  repo: string,
  branch?: string,
): Promise<ResolvedAccess | null> {
  const collaborator = await db.query.collaboratorTable.findFirst({
    where: collaboratorMatchesUserForRepo(user, owner, repo),
  });
  if (!collaborator) return null;

  if (collaborator.branch && branch && collaborator.branch !== branch) {
    return null;
  }

  const grants = await db.query.collaboratorGrantTable.findMany({
    where: eq(collaboratorGrantTable.collaboratorId, collaborator.id),
  });

  return {
    role: isRole(collaborator.role) ? collaborator.role : "editor",
    source: "collaborator",
    branch: collaborator.branch,
    collaboratorId: collaborator.id,
    grants: grants
      .filter((g) =>
        g.scopeType === "collection" || g.scopeType === "file" || g.scopeType === "media",
      )
      .map((g) => ({
        scopeType: g.scopeType as ScopeType,
        scopeValue: g.scopeValue,
        permission: g.permission as Permission,
      })),
  };
}

export function hasPermission(
  access: ResolvedAccess,
  permission: Permission,
  scope?: { type: ScopeType; name?: string },
): boolean {
  // owner shortcut
  if (access.source === "github-owner" || access.role === "owner") return true;

  // role baseline
  const roleHas = ROLE_DEFAULT_PERMS[access.role]?.includes(permission) ?? false;

  if (!scope) return roleHas;

  const scopedGrants = access.grants.filter((g) => g.scopeType === scope.type);
  if (scopedGrants.length === 0) {
    // No scoped grants for this type → fall back to role baseline.
    return roleHas;
  }

  // If there *are* scoped grants for this type, the user must have an explicit
  // matching grant (or a wildcard "*") at the requested permission level or higher.
  const matches = scopedGrants.filter(
    (g) => g.scopeValue === "*" || (scope.name && g.scopeValue === scope.name),
  );
  if (matches.length === 0) return false;

  const order: Permission[] = ["read", "write", "publish", "admin"];
  const required = order.indexOf(permission);
  return matches.some((m) => order.indexOf(m.permission) >= required);
}

export function highestRole(...roles: (Role | undefined | null)[]): Role {
  let best: Role = "viewer";
  for (const r of roles) {
    if (!r) continue;
    if (ROLE_RANKS[r] > ROLE_RANKS[best]) best = r;
  }
  return best;
}

export function canManageCollaborators(access: ResolvedAccess): boolean {
  return access.role === "owner" || hasPermission(access, "admin");
}
