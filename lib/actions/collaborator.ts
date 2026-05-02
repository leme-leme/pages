"use server";

import { auth } from "@/lib/auth";
import { materializeHeaders } from "@/lib/session-server";
import { getInstallationRepos, getInstallations } from "@/lib/github-app";
import { requireGithubRepoWriteAccess, resolveRepoAccess } from "@/lib/authz-server";
import { canManageCollaborators, type Role } from "@/lib/permissions";
import { recordAuditEvent } from "@/lib/audit";
import { InviteEmailTemplate } from "@/components/email/invite";
import { CollaboratorAddedEmailTemplate } from "@/components/email/collaborator-added";
import { render } from "@react-email/render";
import { sendEmail } from "@/lib/mailer";
import { getBaseUrl } from "@/lib/base-url";
import { db } from "@/db";
import { and, eq, sql } from "drizzle-orm";
import { collaboratorTable, collaboratorGrantTable, verificationTable } from "@/db/schema";
import { z } from "zod";
import { randomBytes, randomUUID } from "crypto";
import { findVerifiedUserByEmail, normalizeEmail } from "@/lib/collaborator-access";

const VALID_ROLES: Role[] = ["owner", "editor", "author", "viewer"];

const parseInviteEmails = (raw: FormDataEntryValue | null) => {
  const value = typeof raw === "string" ? raw : "";
  const parts = value
    .split(/[\n,]+/)
    .map((part) => part.trim())
    .filter(Boolean);

  const unique = Array.from(new Set(parts.map((email) => email.toLowerCase())));
  return z.array(z.string().email()).safeParse(unique);
};

const parseRole = (raw: FormDataEntryValue | null): Role => {
  const value = typeof raw === "string" ? raw : "";
  return (VALID_ROLES as string[]).includes(value) ? (value as Role) : "editor";
};

const parseBranch = (raw: FormDataEntryValue | null): string | null => {
  const value = typeof raw === "string" ? raw.trim() : "";
  return value === "" || value === "*" ? null : value;
};

const parseGrants = (raw: FormDataEntryValue | null) => {
  const value = typeof raw === "string" ? raw : "";
  if (!value.trim()) return [] as { scopeType: "collection" | "file" | "media"; scopeValue: string; permission: "read" | "write" | "publish" | "admin" }[];
  try {
    const parsed = JSON.parse(value);
    return z.array(z.object({
      scopeType: z.enum(["collection", "file", "media"]),
      scopeValue: z.string().min(1),
      permission: z.enum(["read", "write", "publish", "admin"]).default("write"),
    })).parse(parsed);
  } catch {
    return [];
  }
};

// For owner-level invites we still need the GitHub installation context
// (so that the magic link works for non-GitHub identities). For
// delegated invites the existing user just needs admin on the repo.
const assertRepoInInstallation = async (
  user: { id: string; githubUsername?: string | null },
  owner: string,
  repo: string,
) => {
  const { token, repoAccess } = await requireGithubRepoWriteAccess(
    user,
    owner,
    repo,
    "You must be signed in with GitHub to manage collaborators.",
  );
  const installations = await getInstallations(token, [owner]);
  if (installations.length !== 1) throw new Error(`"${owner}" is not part of your GitHub App installations`);
  const installationRepos = await getInstallationRepos(token, installations[0].id);
  const isInstalledForRepo = installationRepos.some((installationRepo) =>
    installationRepo.id === repoAccess.repoId ||
    (
      installationRepo.owner?.login?.toLowerCase() === owner.toLowerCase() &&
      installationRepo.name?.toLowerCase() === repo.toLowerCase()
    )
  );
  if (!isInstalledForRepo) throw new Error(`"${owner}/${repo}" is not part of your Pages CMS installation.`);

  return { repoAccess, installation: installations[0] };
};

// Lighter-weight check used by delegated invites: any caller with admin
// permission (via owner role or admin grant) can invite. Falls back to
// `assertRepoInInstallation` if the caller is the GitHub owner so we
// still capture the installation row for new invites.
const resolveInviteContext = async (
  user: { id: string; email: string; githubUsername?: string | null },
  owner: string,
  repo: string,
) => {
  const access = await resolveRepoAccess(user, owner, repo);
  if (!canManageCollaborators(access)) {
    throw new Error("You do not have permission to manage collaborators on this repository.");
  }

  if (access.source === "github-owner" || access.source === "github-write") {
    return assertRepoInInstallation(user, owner, repo);
  }

  // Delegated invite: reuse installation/owner ids from an existing collaborator row.
  const sibling = await db.query.collaboratorTable.findFirst({
    where: and(
      sql`lower(${collaboratorTable.owner}) = lower(${owner})`,
      sql`lower(${collaboratorTable.repo}) = lower(${repo})`,
    ),
  });
  if (!sibling) {
    throw new Error("Cannot delegate invite: repository has no installation context yet.");
  }
  return {
    repoAccess: {
      repoId: sibling.repoId ?? 0,
      ownerId: sibling.ownerId,
      ownerLogin: sibling.owner,
      repoName: sibling.repo,
      ownerType: sibling.type as "user" | "org",
    },
    installation: { id: sibling.installationId },
  };
};

const getDisplayNameFromEmail = (email: string) => {
  const localPart = email.split("@")[0]?.trim();
  return localPart || email;
};

const generateMagicLinkToken = () => {
  const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
  const bytes = randomBytes(32);
  let token = "";
  for (let i = 0; i < 32; i += 1) token += alphabet[bytes[i] % alphabet.length];
  return token;
};

const createCollaboratorInviteMagicLink = async ({
  email,
  owner,
  repo,
  baseUrl,
}: {
  email: string;
  owner: string;
  repo: string;
  baseUrl: string;
}) => {
  const token = generateMagicLinkToken();
  const redirectPath = `/${owner}/${repo}`;
  const expiresAt = new Date(
    Date.now() + ((Number(process.env.COLLABORATOR_INVITE_LINK_EXPIRES_IN) || 86400) * 1000),
  );

  await db.insert(verificationTable).values({
    id: randomUUID(),
    identifier: token,
    value: JSON.stringify({
      email,
      name: getDisplayNameFromEmail(email),
      owner,
      repo,
      source: "collaborator-invite",
    }),
    expiresAt,
  });

  const inviteUrl = new URL("/sign-in/collaborator", baseUrl);
  inviteUrl.searchParams.set("token", token);
  inviteUrl.searchParams.set("email", email);
  inviteUrl.searchParams.set("owner", owner);
  inviteUrl.searchParams.set("repo", repo);
  inviteUrl.searchParams.set("redirect", redirectPath);
  return inviteUrl.toString();
};

const handleAddCollaborator = async (prevState: any, formData: FormData) => {
  try {
    const session = await auth.api.getSession({ headers: await materializeHeaders() });
    const user = session?.user;
    if (!user) throw new Error("You must be signed in to invite collaborators.");

    const ownerAndRepo = z.object({
      owner: z.string().trim().min(1),
      repo: z.string().trim().min(1),
    }).safeParse({
      owner: formData.get("owner"),
      repo: formData.get("repo"),
    });
    if (!ownerAndRepo.success) throw new Error("Invalid owner and/or repo");

    const owner = ownerAndRepo.data.owner;
    const repo = ownerAndRepo.data.repo;
    const role = parseRole(formData.get("role"));
    const branch = parseBranch(formData.get("branch"));
    const grants = parseGrants(formData.get("grants"));

    const emailsValidation = parseInviteEmails(formData.get("emails") ?? formData.get("email"));
    if (!emailsValidation.success || emailsValidation.data.length === 0) {
      throw new Error("Invalid email list");
    }
    const emails = emailsValidation.data;

    const { repoAccess, installation } = await resolveInviteContext(
      { id: user.id, email: user.email!, githubUsername: user.githubUsername },
      owner,
      repo,
    );

    const baseUrl = getBaseUrl();
    const repoUrl = new URL(`/${owner}/${repo}`, baseUrl).toString();
    const createdCollaborators: (typeof collaboratorTable.$inferSelect)[] = [];
    const errors: string[] = [];
    let immediateAccessCount = 0;
    let pendingInviteCount = 0;

    for (const email of emails) {
      const normalizedEmail = normalizeEmail(email);
      const existingUser = await findVerifiedUserByEmail(normalizedEmail);
      const existing = await db.query.collaboratorTable.findFirst({
        where: and(
          eq(collaboratorTable.ownerId, repoAccess.ownerId),
          eq(collaboratorTable.repoId, repoAccess.repoId),
          sql`lower(${collaboratorTable.email}) = lower(${normalizedEmail})`,
        ),
      });
      if (existing) {
        if (existingUser && existing.userId !== existingUser.id) {
          const updated = await db.update(collaboratorTable)
            .set({ userId: existingUser.id, role, branch })
            .where(eq(collaboratorTable.id, existing.id))
            .returning();
          if (updated.length > 0) {
            createdCollaborators.push(...updated);
            immediateAccessCount += 1;
          }
        }
        errors.push(`${normalizedEmail} is already invited to "${owner}/${repo}".`);
        continue;
      }

      if (!existingUser) {
        const inviteUrl = await createCollaboratorInviteMagicLink({
          email: normalizedEmail,
          owner,
          repo,
          baseUrl,
        });
        try {
          const html = await render(InviteEmailTemplate({
            inviteUrl,
            repoName: `${owner}/${repo}`,
            email: normalizedEmail,
            invitedByName: user.name || user.githubUsername || user.email,
            invitedByUrl: user.githubUsername ? `https://github.com/${user.githubUsername}` : "",
          }));
          await sendEmail({ to: normalizedEmail, subject: `Join "${owner}/${repo}" on Pages CMS`, html });
        } catch (error: any) {
          console.error(`Failed to send invitation email to ${normalizedEmail}:`, error.message);
          errors.push(`${normalizedEmail}: ${error.message}`);
          continue;
        }
      } else {
        try {
          const html = await render(CollaboratorAddedEmailTemplate({
            email: normalizedEmail,
            repoName: `${owner}/${repo}`,
            repoUrl,
            invitedByName: user.name || user.githubUsername || user.email,
            invitedByUrl: user.githubUsername ? `https://github.com/${user.githubUsername}` : "",
          }));
          await sendEmail({ to: normalizedEmail, subject: `You were added to "${owner}/${repo}" on Pages CMS`, html });
        } catch (error: any) {
          console.error(`Failed to send collaborator notification email to ${normalizedEmail}:`, error.message);
          errors.push(`${normalizedEmail}: ${error.message}`);
        }
      }

      const inserted = await db.insert(collaboratorTable).values({
        type: repoAccess.ownerType,
        installationId: installation.id,
        ownerId: repoAccess.ownerId,
        repoId: repoAccess.repoId,
        owner: repoAccess.ownerLogin,
        repo: repoAccess.repoName,
        branch,
        email: normalizedEmail,
        userId: existingUser?.id ?? null,
        invitedBy: user.id,
        role,
      }).returning();

      if (inserted.length > 0) {
        const newRow = inserted[0];
        if (grants.length > 0) {
          await db.insert(collaboratorGrantTable).values(grants.map((g) => ({
            collaboratorId: newRow.id,
            scopeType: g.scopeType,
            scopeValue: g.scopeValue,
            permission: g.permission,
          })));
        }
        createdCollaborators.push(newRow);
        if (existingUser) {
          immediateAccessCount += 1;
        } else {
          pendingInviteCount += 1;
        }
        await recordAuditEvent({
          actor: { userId: user.id, email: user.email },
          action: "collaborator.invite",
          resourceType: "collaborator",
          resourceId: String(newRow.id),
          owner, repo, branch: branch ?? undefined,
          after: { email: normalizedEmail, role, branch, grants: grants.length },
        });
      }
    }

    if (createdCollaborators.length === 0) {
      throw new Error(errors.join(" "));
    }

    return {
      message:
        immediateAccessCount > 0 && pendingInviteCount > 0
          ? `${immediateAccessCount} collaborator${immediateAccessCount === 1 ? "" : "s"} added immediately and ${pendingInviteCount} invite${pendingInviteCount === 1 ? "" : "s"} sent for "${owner}/${repo}".`
          : immediateAccessCount > 0
            ? `${immediateAccessCount} collaborator${immediateAccessCount === 1 ? "" : "s"} added to "${owner}/${repo}".`
            : pendingInviteCount === 1
              ? `${createdCollaborators[0].email} invited to "${owner}/${repo}".`
              : `${pendingInviteCount} collaborators invited to "${owner}/${repo}".`,
      data: createdCollaborators,
      errors,
    };
  } catch (error: any) {
    console.error(error);
    return { error: error.message };
  }
};

const handleRemoveCollaborator = async (collaboratorId: number, owner: string, repo: string) => {
  try {
    const session = await auth.api.getSession({ headers: await materializeHeaders() });
    const user = session?.user;
    if (!user) throw new Error("You must be signed in to manage collaborators.");

    const access = await resolveRepoAccess(
      { id: user.id, email: user.email!, githubUsername: user.githubUsername },
      owner,
      repo,
    );
    if (!canManageCollaborators(access)) {
      throw new Error("You do not have permission to manage collaborators on this repository.");
    }

    const collaborator = await db.query.collaboratorTable.findFirst({
      where: eq(collaboratorTable.id, collaboratorId),
    });
    if (!collaborator) throw new Error("Collaborator not found");

    const deletedCollaborator = await db.delete(collaboratorTable).where(
      and(
        eq(collaboratorTable.id, collaboratorId),
        sql`lower(${collaboratorTable.owner}) = lower(${owner})`,
        sql`lower(${collaboratorTable.repo}) = lower(${repo})`,
      ),
    ).returning();

    if (!deletedCollaborator || deletedCollaborator.length === 0) {
      throw new Error("Failed to delete collaborator");
    }

    await recordAuditEvent({
      actor: { userId: user.id, email: user.email },
      action: "collaborator.remove",
      resourceType: "collaborator",
      resourceId: String(collaboratorId),
      owner, repo,
      before: { email: collaborator.email, role: collaborator.role, branch: collaborator.branch },
    });

    return { message: `Invitation to ${collaborator.email} for "${owner}/${repo}" successfully removed.` };
  } catch (error: any) {
    console.error(error);
    return { error: error.message };
  }
};

const handleResendCollaboratorInvite = async (collaboratorId: number, owner: string, repo: string) => {
  try {
    const session = await auth.api.getSession({ headers: await materializeHeaders() });
    const user = session?.user;
    if (!user) throw new Error("You must be signed in to resend collaborator invites.");

    const access = await resolveRepoAccess(
      { id: user.id, email: user.email!, githubUsername: user.githubUsername },
      owner,
      repo,
    );
    if (!canManageCollaborators(access)) {
      throw new Error("You do not have permission to manage collaborators on this repository.");
    }

    const collaborator = await db.query.collaboratorTable.findFirst({
      where: eq(collaboratorTable.id, collaboratorId),
    });
    if (!collaborator) throw new Error("Collaborator not found");

    if (collaborator.owner.toLowerCase() !== owner.toLowerCase() ||
        collaborator.repo.toLowerCase() !== repo.toLowerCase()) {
      throw new Error("Collaborator does not belong to this repository.");
    }

    const baseUrl = getBaseUrl();
    const inviteUrl = await createCollaboratorInviteMagicLink({
      email: collaborator.email, owner, repo, baseUrl,
    });

    const html = await render(InviteEmailTemplate({
      inviteUrl,
      repoName: `${owner}/${repo}`,
      email: collaborator.email,
      invitedByName: user.name || user.githubUsername || user.email,
      invitedByUrl: user.githubUsername ? `https://github.com/${user.githubUsername}` : "",
    }));

    await sendEmail({
      to: collaborator.email,
      subject: `Join "${owner}/${repo}" on Pages CMS`,
      html,
    });

    return { message: `Invitation email resent to ${collaborator.email}.` };
  } catch (error: any) {
    console.error(error);
    return { error: error.message };
  }
};

const updateRoleSchema = z.object({
  role: z.enum(["owner", "editor", "author", "viewer"]),
  branch: z.string().optional().nullable(),
});

const handleUpdateCollaboratorRole = async (
  collaboratorId: number,
  owner: string,
  repo: string,
  payload: { role: Role; branch?: string | null },
) => {
  try {
    const session = await auth.api.getSession({ headers: await materializeHeaders() });
    const user = session?.user;
    if (!user) throw new Error("You must be signed in to manage collaborators.");

    const access = await resolveRepoAccess(
      { id: user.id, email: user.email!, githubUsername: user.githubUsername },
      owner,
      repo,
    );
    if (!canManageCollaborators(access)) {
      throw new Error("You do not have permission to manage collaborators on this repository.");
    }

    const parsed = updateRoleSchema.parse(payload);
    const branch = parsed.branch === undefined ? undefined : (parsed.branch && parsed.branch.trim() !== "" ? parsed.branch.trim() : null);

    const before = await db.query.collaboratorTable.findFirst({
      where: eq(collaboratorTable.id, collaboratorId),
    });
    if (!before) throw new Error("Collaborator not found");

    await db.update(collaboratorTable)
      .set({ role: parsed.role, ...(branch !== undefined ? { branch } : {}) })
      .where(eq(collaboratorTable.id, collaboratorId));

    await recordAuditEvent({
      actor: { userId: user.id, email: user.email },
      action: "collaborator.update-role",
      resourceType: "collaborator",
      resourceId: String(collaboratorId),
      owner, repo,
      before: { role: before.role, branch: before.branch },
      after: { role: parsed.role, branch: branch ?? before.branch },
    });

    return { message: "Collaborator updated." };
  } catch (error: any) {
    console.error(error);
    return { error: error.message };
  }
};

const grantsSchema = z.array(z.object({
  scopeType: z.enum(["collection", "file", "media"]),
  scopeValue: z.string().min(1),
  permission: z.enum(["read", "write", "publish", "admin"]).default("write"),
}));

const handleSetCollaboratorGrants = async (
  collaboratorId: number,
  owner: string,
  repo: string,
  grants: unknown,
) => {
  try {
    const session = await auth.api.getSession({ headers: await materializeHeaders() });
    const user = session?.user;
    if (!user) throw new Error("You must be signed in to manage collaborators.");

    const access = await resolveRepoAccess(
      { id: user.id, email: user.email!, githubUsername: user.githubUsername },
      owner,
      repo,
    );
    if (!canManageCollaborators(access)) {
      throw new Error("You do not have permission to manage collaborators on this repository.");
    }

    const parsed = grantsSchema.parse(grants);

    const before = await db.query.collaboratorGrantTable.findMany({
      where: eq(collaboratorGrantTable.collaboratorId, collaboratorId),
    });

    await db.delete(collaboratorGrantTable).where(eq(collaboratorGrantTable.collaboratorId, collaboratorId));
    if (parsed.length > 0) {
      await db.insert(collaboratorGrantTable).values(parsed.map((g) => ({
        collaboratorId,
        scopeType: g.scopeType,
        scopeValue: g.scopeValue,
        permission: g.permission,
      })));
    }

    await recordAuditEvent({
      actor: { userId: user.id, email: user.email },
      action: "collaborator.update-grants",
      resourceType: "collaborator",
      resourceId: String(collaboratorId),
      owner, repo,
      before: before.map((g) => ({ scopeType: g.scopeType, scopeValue: g.scopeValue, permission: g.permission })),
      after: parsed,
    });

    return { message: "Permissions updated." };
  } catch (error: any) {
    console.error(error);
    return { error: error.message };
  }
};

export {
  handleAddCollaborator,
  handleRemoveCollaborator,
  handleResendCollaboratorInvite,
  handleUpdateCollaboratorRole,
  handleSetCollaboratorGrants,
};
