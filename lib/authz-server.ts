import "server-only";

import type { User } from "@/types/user";
import { assertGithubIdentity, hasGithubIdentity } from "@/lib/authz-shared";
import { getUserToken } from "@/lib/token";
import { createOctokitInstance } from "@/lib/utils/octokit";
import {
  hasPermission,
  resolveAccessForUser,
  type Permission,
  type ResolvedAccess,
  type Role,
  type ScopeType,
} from "@/lib/permissions";

const requireGithubUserToken = async (
  user: Pick<User, "id" | "githubUsername">,
  identityErrorMessage = "Only GitHub users can perform this action.",
) => {
  assertGithubIdentity(user, identityErrorMessage);
  return getUserToken(user.id);
};

const requireGithubRepoWriteAccess = async (
  user: Pick<User, "id" | "githubUsername">,
  owner: string,
  repo: string,
  identityErrorMessage = "Only GitHub users can perform this action.",
) => {
  const token = await requireGithubUserToken(user, identityErrorMessage);
  const octokit = createOctokitInstance(token);
  const response = await octokit.rest.repos.get({ owner, repo });

  if (!response.data.permissions?.push) {
    throw new Error(`You do not have write access to "${owner}/${repo}".`);
  }

  const repoAccess = {
    repoId: response.data.id,
    ownerId: response.data.owner.id,
    ownerLogin: response.data.owner.login,
    repoName: response.data.name,
    ownerType: response.data.owner.type === "User" ? "user" : "org",
  };

  return { token, repoAccess };
};

// Single source of truth for "what can this user do in this repo right now".
// Order of precedence:
//   1. GitHub repo admin (admin = owner role + admin permission).
//   2. GitHub repo writer (push) → editor.
//   3. Local collaborator row (D1) → role + grants.
//   4. None.
const resolveRepoAccess = async (
  user: Pick<User, "id" | "email" | "githubUsername">,
  owner: string,
  repo: string,
  branch?: string,
): Promise<ResolvedAccess> => {
  if (hasGithubIdentity(user)) {
    try {
      const token = await getUserToken(user.id);
      const octokit = createOctokitInstance(token);
      const response = await octokit.rest.repos.get({ owner, repo });
      const perms = response.data.permissions;
      if (perms?.admin) {
        return { role: "owner", source: "github-owner", grants: [] };
      }
      if (perms?.push) {
        return { role: "editor", source: "github-write", grants: [] };
      }
    } catch {
      // fall through to local lookup
    }
  }

  const local = await resolveAccessForUser(user, owner, repo, branch);
  if (local) return local;

  return { role: "viewer", source: "none", grants: [] };
};

const requirePermission = async (
  user: Pick<User, "id" | "email" | "githubUsername">,
  owner: string,
  repo: string,
  permission: Permission,
  scope?: { type: ScopeType; name?: string },
  branch?: string,
): Promise<ResolvedAccess> => {
  const access = await resolveRepoAccess(user, owner, repo, branch);
  if (access.source === "none" || !hasPermission(access, permission, scope)) {
    const error = new Error(
      scope
        ? `You do not have ${permission} access to ${scope.type} "${scope.name ?? "*"}" in "${owner}/${repo}".`
        : `You do not have ${permission} access to "${owner}/${repo}".`,
    ) as Error & { status?: number };
    error.status = access.source === "none" ? 403 : 403;
    throw error;
  }
  return access;
};

export type { Permission, Role, ScopeType, ResolvedAccess };
export { requireGithubUserToken, requireGithubRepoWriteAccess, resolveRepoAccess, requirePermission };
