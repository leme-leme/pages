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
  invitedBy: text("invited_by").references(() => userTable.id),
  // Coarse role: owner | editor | author | viewer. Fine-grained access lives in collaborator_grant.
  role: text("role").notNull().default("editor"),
}, table => ({
  idx_collaborator_owner_repo_email: index("idx_collaborator_owner_repo_email").on(table.owner, table.repo, table.email),
  idx_collaborator_userId: index("idx_collaborator_userId").on(table.userId),
  uq_collaborator_owner_repo_email_ci: uniqueIndex("uq_collaborator_owner_repo_email_ci").on(
    sql`lower(${table.owner})`,
    sql`lower(${table.repo})`,
    sql`lower(${table.email})`,
  ),
}));

// Per-collaborator grants scoped to a collection / file / media name.
// scopeType="collection"|"file"|"media", scopeValue = schema name (or "*" for all).
// permission = "read"|"write".
const collaboratorGrantTable = sqliteTable("collaborator_grant", {
  id: integer("id").primaryKey({ autoIncrement: true }),
  collaboratorId: integer("collaborator_id").notNull().references(() => collaboratorTable.id, { onDelete: "cascade" }),
  scopeType: text("scope_type").notNull(),
  scopeValue: text("scope_value").notNull(),
  permission: text("permission").notNull().default("write"),
  createdAt: integer("created_at", { mode: "timestamp" }).notNull().default(now),
}, table => ({
  idx_collaborator_grant_collaboratorId: index("idx_collaborator_grant_collaboratorId").on(table.collaboratorId),
  uq_collaborator_grant: uniqueIndex("uq_collaborator_grant").on(
    table.collaboratorId, table.scopeType, table.scopeValue, table.permission,
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
  // Most recent moment a content reference to this cache row was observed (for orphan GC).
  referencedAt: integer("referenced_at", { mode: "timestamp" }),
}, table => ({
  idx_cache_file_owner_repo_branch_parentPath: index("idx_cache_file_owner_repo_branch_parentPath").on(table.owner, table.repo, table.branch, table.parentPath),
  idx_cache_file_owner_repo_branch_path: uniqueIndex("idx_cache_file_owner_repo_branch_path").on(table.owner, table.repo, table.branch, table.path),
  idx_cache_file_provider: index("idx_cache_file_provider").on(table.provider),
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

// Per-project S3-compatible storage configuration. Credentials encrypted at rest.
const projectStorageConfigTable = sqliteTable("project_storage_config", {
  id: integer("id").primaryKey({ autoIncrement: true }),
  owner: text("owner").notNull(),
  repo: text("repo").notNull(),
  branch: text("branch").notNull().default(""),
  endpoint: text("endpoint").notNull(),
  region: text("region").notNull().default("us-east-1"),
  bucket: text("bucket").notNull(),
  prefix: text("prefix").notNull().default(""),
  forcePathStyle: integer("force_path_style", { mode: "boolean" }).notNull().default(true),
  visibility: text("visibility").notNull().default("public"),
  // AES-GCM encrypted credentials.
  accessKeyCiphertext: text("access_key_ciphertext").notNull(),
  accessKeyIv: text("access_key_iv").notNull(),
  secretKeyCiphertext: text("secret_key_ciphertext").notNull(),
  secretKeyIv: text("secret_key_iv").notNull(),
  // Soft caps; -1 = no limit.
  thresholdBytes: integer("threshold_bytes").notNull().default(26214400),
  maxFileBytes: integer("max_file_bytes").notNull().default(-1),
  // Optional public base URL for direct CDN reads (skips proxy).
  publicBaseUrl: text("public_base_url"),
  createdAt: integer("created_at", { mode: "timestamp" }).notNull().default(now),
  updatedAt: integer("updated_at", { mode: "timestamp" }).notNull().default(now),
}, table => ({
  uq_project_storage_owner_repo_branch: uniqueIndex("uq_project_storage_owner_repo_branch").on(
    sql`lower(${table.owner})`,
    sql`lower(${table.repo})`,
    table.branch,
  ),
}));

// Append-only audit trail. before/after stored as JSON strings.
const auditEventTable = sqliteTable("audit_event", {
  id: integer("id").primaryKey({ autoIncrement: true }),
  actorUserId: text("actor_user_id").references(() => userTable.id, { onDelete: "set null" }),
  actorEmail: text("actor_email"),
  actorType: text("actor_type").notNull().default("user"), // user | api_token | system
  action: text("action").notNull(),
  resourceType: text("resource_type").notNull(),
  resourceId: text("resource_id"),
  owner: text("owner"),
  repo: text("repo"),
  branch: text("branch"),
  before: text("before"),
  after: text("after"),
  metadata: text("metadata"),
  ipAddress: text("ip_address"),
  userAgent: text("user_agent"),
  createdAt: integer("created_at", { mode: "timestamp" }).notNull().default(now),
}, table => ({
  idx_audit_event_owner_repo_createdAt: index("idx_audit_event_owner_repo_createdAt").on(table.owner, table.repo, table.createdAt),
  idx_audit_event_actorUserId: index("idx_audit_event_actorUserId").on(table.actorUserId),
  idx_audit_event_action: index("idx_audit_event_action").on(table.action),
  idx_audit_event_resource: index("idx_audit_event_resource").on(table.resourceType, table.resourceId),
}));

// Hashed personal access tokens for headless usage. Token plaintext is shown
// once at creation; only sha256 lives in the DB.
const apiTokenTable = sqliteTable("api_token", {
  id: integer("id").primaryKey({ autoIncrement: true }),
  userId: text("user_id").notNull().references(() => userTable.id, { onDelete: "cascade" }),
  name: text("name").notNull(),
  prefix: text("prefix").notNull(), // first 8 chars for UI display
  hash: text("hash").notNull().unique(), // sha256 hex of the full token
  owner: text("owner"),
  repo: text("repo"),
  branch: text("branch"),
  role: text("role").notNull().default("editor"),
  scopes: text("scopes").notNull().default("[]"), // JSON: [{scopeType, scopeValue, permission}]
  lastUsedAt: integer("last_used_at", { mode: "timestamp" }),
  expiresAt: integer("expires_at", { mode: "timestamp" }),
  revokedAt: integer("revoked_at", { mode: "timestamp" }),
  createdAt: integer("created_at", { mode: "timestamp" }).notNull().default(now),
}, table => ({
  idx_api_token_userId: index("idx_api_token_userId").on(table.userId),
  idx_api_token_owner_repo: index("idx_api_token_owner_repo").on(table.owner, table.repo),
}));

// Bytes counters per project. Updated on upload + on /api/s3 GET.
const storageUsageTable = sqliteTable("storage_usage", {
  id: integer("id").primaryKey({ autoIncrement: true }),
  owner: text("owner").notNull(),
  repo: text("repo").notNull(),
  branch: text("branch").notNull().default(""),
  bytesStored: integer("bytes_stored").notNull().default(0),
  bytesEgressed: integer("bytes_egressed").notNull().default(0),
  fileCount: integer("file_count").notNull().default(0),
  lastReconciledAt: integer("last_reconciled_at", { mode: "timestamp" }),
  updatedAt: integer("updated_at", { mode: "timestamp" }).notNull().default(now),
}, table => ({
  uq_storage_usage_owner_repo_branch: uniqueIndex("uq_storage_usage_owner_repo_branch").on(
    sql`lower(${table.owner})`,
    sql`lower(${table.repo})`,
    table.branch,
  ),
}));

// Per-project tags injected into the *deployed site* (not the CMS itself).
// Each provider is independently configurable; nulls = disabled.
const projectAnalyticsConfigTable = sqliteTable("project_analytics_config", {
  id: integer("id").primaryKey({ autoIncrement: true }),
  owner: text("owner").notNull(),
  repo: text("repo").notNull(),
  branch: text("branch").notNull().default(""),
  // Google Analytics 4 measurement ID (G-XXXXXXX).
  ga4MeasurementId: text("ga4_measurement_id"),
  // Plausible: site domain registered in plausible (e.g. "example.com").
  plausibleDomain: text("plausible_domain"),
  // Plausible self-hosted base URL (defaults to https://plausible.io).
  plausibleApiHost: text("plausible_api_host"),
  // Cloudflare Web Analytics beacon token (the "token" attr on their script).
  cfBeaconToken: text("cf_beacon_token"),
  // When true, the snippet emits a small consent banner and only loads the
  // tag after the user opts in. When false the tag loads immediately, but
  // the snippet still respects DNT / Sec-GPC.
  requireConsent: integer("require_consent", { mode: "boolean" }).notNull().default(true),
  // When true, DNT/Sec-GPC suppress the tag entirely.
  honorDnt: integer("honor_dnt", { mode: "boolean" }).notNull().default(true),
  createdAt: integer("created_at", { mode: "timestamp" }).notNull().default(now),
  updatedAt: integer("updated_at", { mode: "timestamp" }).notNull().default(now),
}, table => ({
  uq_project_analytics_owner_repo_branch: uniqueIndex("uq_project_analytics_owner_repo_branch").on(
    sql`lower(${table.owner})`,
    sql`lower(${table.repo})`,
    table.branch,
  ),
}));

// Daily aggregates derived from Analytics Engine. Keeps history beyond AE's
// 90-day window. Written by the daily rollup cron.
const analyticsRollupTable = sqliteTable("analytics_rollup", {
  id: integer("id").primaryKey({ autoIncrement: true }),
  date: text("date").notNull(), // YYYY-MM-DD UTC
  owner: text("owner").notNull().default(""),
  repo: text("repo").notNull().default(""),
  eventType: text("event_type").notNull(),
  count: integer("count").notNull().default(0),
  bytes: integer("bytes").notNull().default(0),
  uniqueActors: integer("unique_actors").notNull().default(0),
  createdAt: integer("created_at", { mode: "timestamp" }).notNull().default(now),
}, table => ({
  uq_analytics_rollup: uniqueIndex("uq_analytics_rollup").on(
    table.date, table.owner, table.repo, table.eventType,
  ),
  idx_analytics_rollup_date: index("idx_analytics_rollup_date").on(table.date),
}));

// Token-bucket rate limiter state. Keyed by `${userId}:${owner}/${repo}`.
const rateLimitTable = sqliteTable("rate_limit", {
  id: integer("id").primaryKey({ autoIncrement: true }),
  bucket: text("bucket").notNull().unique(),
  tokens: integer("tokens").notNull(),
  refilledAt: integer("refilled_at", { mode: "timestamp" }).notNull().default(now),
}, table => ({
  idx_rate_limit_bucket: uniqueIndex("idx_rate_limit_bucket").on(table.bucket),
}));

export {
  userTable,
  sessionTable,
  accountTable,
  verificationTable,
  githubInstallationTokenTable,
  collaboratorTable,
  collaboratorGrantTable,
  configTable,
  cacheFileTable,
  cacheFileMetaTable,
  cachePermissionTable,
  actionRunTable,
  projectStorageConfigTable,
  auditEventTable,
  apiTokenTable,
  storageUsageTable,
  rateLimitTable,
  projectAnalyticsConfigTable,
  analyticsRollupTable,
};
