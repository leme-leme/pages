import {
  sqliteTable,
  text,
  integer,
  index,
  uniqueIndex,
} from "drizzle-orm/sqlite-core";
import { sql } from "drizzle-orm";

const now = sql`(unixepoch())`;

const userTable = sqliteTable("user", {
  id: text("id").notNull().primaryKey(),
  name: text("name").notNull(),
  image: text("image"),
  githubUsername: text("github_username"),
  email: text("email").notNull().unique(),
  emailVerified: integer("email_verified", { mode: "boolean" }).notNull().default(false),
  createdAt: integer("created_at", { mode: "timestamp" }).notNull().default(now),
  updatedAt: integer("updated_at", { mode: "timestamp" }).notNull().default(now)
});

const sessionTable = sqliteTable("session", {
  id: text("id").notNull().primaryKey(),
  expiresAt: integer("expires_at", { mode: "timestamp" }).notNull(),
  token: text("token").notNull().unique(),
  createdAt: integer("created_at", { mode: "timestamp" }).notNull().default(now),
  updatedAt: integer("updated_at", { mode: "timestamp" }).notNull().default(now),
  ipAddress: text("ip_address"),
  userAgent: text("user_agent"),
  userId: text("user_id").notNull().references(() => userTable.id, { onDelete: "cascade" })
}, table => ({
  idx_session_userId: index("idx_session_userId").on(table.userId)
}));

const accountTable = sqliteTable("account", {
  id: text("id").notNull().primaryKey(),
  accountId: text("account_id").notNull(),
  providerId: text("provider_id").notNull(),
  userId: text("user_id").notNull().references(() => userTable.id, { onDelete: "cascade" }),
  accessToken: text("access_token"),
  refreshToken: text("refresh_token"),
  idToken: text("id_token"),
  accessTokenExpiresAt: integer("access_token_expires_at", { mode: "timestamp" }),
  refreshTokenExpiresAt: integer("refresh_token_expires_at", { mode: "timestamp" }),
  scope: text("scope"),
  password: text("password"),
  createdAt: integer("created_at", { mode: "timestamp" }).notNull().default(now),
  updatedAt: integer("updated_at", { mode: "timestamp" }).notNull().default(now)
}, table => ({
  idx_account_userId: index("idx_account_userId").on(table.userId),
  idx_account_providerId: index("idx_account_providerId").on(table.providerId)
}));

const verificationTable = sqliteTable("verification", {
  id: text("id").notNull().primaryKey(),
  identifier: text("identifier").notNull(),
  value: text("value").notNull(),
  expiresAt: integer("expires_at", { mode: "timestamp" }).notNull(),
  createdAt: integer("created_at", { mode: "timestamp" }).notNull().default(now),
  updatedAt: integer("updated_at", { mode: "timestamp" }).notNull().default(now)
}, table => ({
  idx_verification_identifier: index("idx_verification_identifier").on(table.identifier)
}));

const githubInstallationTokenTable = sqliteTable("github_installation_token", {
  id: integer("id").primaryKey({ autoIncrement: true }),
  ciphertext: text("ciphertext").notNull(),
  iv: text("iv").notNull(),
  installationId: integer("installation_id").notNull(),
  expiresAt: integer("expires_at", { mode: "timestamp" }).notNull()
}, table => ({
  uq_github_installation_token_installationId: uniqueIndex("uq_github_installation_token_installationId").on(table.installationId)
}));

const collaboratorTable = sqliteTable("collaborator", {
  id: integer("id").primaryKey({ autoIncrement: true }),
  type: text("type").notNull(),
  installationId: integer("installation_id").notNull(),
  ownerId: integer("owner_id").notNull(),
  repoId: integer("repo_id"),
  owner: text("owner").notNull(),
  repo: text("repo").notNull(),
  branch: text("branch"),
  email: text("email").notNull(),
  userId: text("user_id").references(() => userTable.id),
  invitedBy: text("invited_by").references(() => userTable.id)
}, table => ({
  idx_collaborator_owner_repo_email: index("idx_collaborator_owner_repo_email").on(table.owner, table.repo, table.email),
  idx_collaborator_userId: index("idx_collaborator_userId").on(table.userId),
  uq_collaborator_owner_repo_email_ci: uniqueIndex("uq_collaborator_owner_repo_email_ci").on(
    sql`lower(${table.owner})`,
    sql`lower(${table.repo})`,
    sql`lower(${table.email})`,
  ),
}));

const configTable = sqliteTable("config", {
  id: integer("id").primaryKey({ autoIncrement: true }),
  owner: text("owner").notNull(),
  repo: text("repo").notNull(),
  branch: text("branch").notNull(),
  sha: text("sha").notNull(),
  version: text("version").notNull(),
  object: text("object").notNull(),
  lastCheckedAt: integer("last_checked_at", { mode: "timestamp" }).notNull().default(now)
}, table => ({
  idx_config_owner_repo_branch: uniqueIndex("idx_config_owner_repo_branch").on(table.owner, table.repo, table.branch)
}));

const cacheFileTable = sqliteTable("cache_file", {
  id: integer("id").primaryKey({ autoIncrement: true }),
  context: text("context").notNull().default('collection'),
  owner: text("owner").notNull(),
  repo: text("repo").notNull(),
  branch: text("branch").notNull(),
  parentPath: text("parent_path").notNull(),
  name: text("name").notNull(),
  path: text("path").notNull(),
  type: text("type").notNull(),
  content: text("content"),
  sha: text("sha"),
  size: integer("size"),
  downloadUrl: text("download_url"),
  commitSha: text('commit_sha'),
  commitTimestamp: integer('commit_timestamp', { mode: "timestamp" }),
  updatedAt: integer("updated_at", { mode: "timestamp" }).notNull(),
  // Storage provider for the file body. "github" = served via raw.githubusercontent
  // ("download_url"). "s3" = stored in S3/MinIO/R2 under "s3_key" and served via /api/s3/.
  provider: text("provider").notNull().default("github"),
  s3Key: text("s3_key"),
}, table => ({
  idx_cache_file_owner_repo_branch_parentPath: index("idx_cache_file_owner_repo_branch_parentPath").on(table.owner, table.repo, table.branch, table.parentPath),
  idx_cache_file_owner_repo_branch_path: uniqueIndex("idx_cache_file_owner_repo_branch_path").on(table.owner, table.repo, table.branch, table.path)
}));

const cacheFileMetaTable = sqliteTable("cache_file_meta", {
  id: integer("id").primaryKey({ autoIncrement: true }),
  owner: text("owner").notNull(),
  repo: text("repo").notNull(),
  branch: text("branch").notNull(),
  path: text("path").notNull().default(""),
  context: text("context").notNull().default("branch"),
  commitSha: text("commit_sha"),
  commitTimestamp: integer("commit_timestamp", { mode: "timestamp" }),
  status: text("status").notNull().default("ok"),
  error: text("error"),
  updatedAt: integer("updated_at", { mode: "timestamp" }).notNull().default(now),
  lastCheckedAt: integer("last_checked_at", { mode: "timestamp" }).notNull().default(now),
}, table => ({
  idx_cache_file_meta_owner_repo_branch_path_context: uniqueIndex("idx_cache_file_meta_owner_repo_branch_path_context").on(table.owner, table.repo, table.branch, table.path, table.context)
}));

const cachePermissionTable = sqliteTable("cache_permission", {
  id: integer("id").primaryKey({ autoIncrement: true }),
  githubId: integer("github_id").notNull(),
  owner: text("owner").notNull(),
  repo: text("repo").notNull(),
  lastUpdated: integer("last_updated", { mode: "timestamp" }).notNull()
}, table => ({
  idx_cache_permission_githubId_owner_repo: uniqueIndex("idx_cache_permission_githubId_owner_repo").on(table.githubId, table.owner, table.repo)
}));

const actionRunTable = sqliteTable("action_run", {
  id: integer("id").primaryKey({ autoIncrement: true }),
  owner: text("owner").notNull(),
  repo: text("repo").notNull(),
  ref: text("ref").notNull(),
  workflowRef: text("workflow_ref").notNull(),
  sha: text("sha").notNull(),
  actionName: text("action_name").notNull(),
  contextType: text("context_type").notNull(),
  contextName: text("context_name"),
  contextPath: text("context_path"),
  workflow: text("workflow").notNull(),
  workflowRunId: integer("workflow_run_id", { mode: "number" }),
  status: text("status").notNull(),
  conclusion: text("conclusion"),
  htmlUrl: text("html_url"),
  triggeredBy: text("triggered_by", { mode: "json" }).notNull(),
  failure: text("failure", { mode: "json" }),
  payload: text("payload", { mode: "json" }).notNull(),
  createdAt: integer("created_at", { mode: "timestamp" }).notNull().default(now),
  updatedAt: integer("updated_at", { mode: "timestamp" }).notNull().default(now),
  completedAt: integer("completed_at", { mode: "timestamp" }),
}, table => ({
  idx_action_run_owner_repo_createdAt: index("idx_action_run_owner_repo_createdAt").on(table.owner, table.repo, table.createdAt),
  idx_action_run_owner_repo_actionName: index("idx_action_run_owner_repo_actionName").on(table.owner, table.repo, table.actionName),
  idx_action_run_owner_repo_status: index("idx_action_run_owner_repo_status").on(table.owner, table.repo, table.status),
  idx_action_run_context: index("idx_action_run_context").on(table.owner, table.repo, table.contextType, table.contextName, table.contextPath),
  idx_action_run_workflowRunId: uniqueIndex("idx_action_run_workflowRunId").on(table.workflowRunId),
}));

export {
  userTable,
  sessionTable,
  accountTable,
  verificationTable,
  githubInstallationTokenTable,
  collaboratorTable,
  configTable,
  cacheFileTable,
  cacheFileMetaTable,
  cachePermissionTable,
  actionRunTable
};
