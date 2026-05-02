CREATE TABLE `api_token` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`user_id` text NOT NULL,
	`name` text NOT NULL,
	`prefix` text NOT NULL,
	`hash` text NOT NULL,
	`owner` text,
	`repo` text,
	`branch` text,
	`role` text DEFAULT 'editor' NOT NULL,
	`scopes` text DEFAULT '[]' NOT NULL,
	`last_used_at` integer,
	`expires_at` integer,
	`revoked_at` integer,
	`created_at` integer DEFAULT (unixepoch()) NOT NULL,
	FOREIGN KEY (`user_id`) REFERENCES `user`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE UNIQUE INDEX `api_token_hash_unique` ON `api_token` (`hash`);--> statement-breakpoint
CREATE INDEX `idx_api_token_userId` ON `api_token` (`user_id`);--> statement-breakpoint
CREATE INDEX `idx_api_token_owner_repo` ON `api_token` (`owner`,`repo`);--> statement-breakpoint
CREATE TABLE `audit_event` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`actor_user_id` text,
	`actor_email` text,
	`actor_type` text DEFAULT 'user' NOT NULL,
	`action` text NOT NULL,
	`resource_type` text NOT NULL,
	`resource_id` text,
	`owner` text,
	`repo` text,
	`branch` text,
	`before` text,
	`after` text,
	`metadata` text,
	`ip_address` text,
	`user_agent` text,
	`created_at` integer DEFAULT (unixepoch()) NOT NULL,
	FOREIGN KEY (`actor_user_id`) REFERENCES `user`(`id`) ON UPDATE no action ON DELETE set null
);
--> statement-breakpoint
CREATE INDEX `idx_audit_event_owner_repo_createdAt` ON `audit_event` (`owner`,`repo`,`created_at`);--> statement-breakpoint
CREATE INDEX `idx_audit_event_actorUserId` ON `audit_event` (`actor_user_id`);--> statement-breakpoint
CREATE INDEX `idx_audit_event_action` ON `audit_event` (`action`);--> statement-breakpoint
CREATE INDEX `idx_audit_event_resource` ON `audit_event` (`resource_type`,`resource_id`);--> statement-breakpoint
CREATE TABLE `collaborator_grant` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`collaborator_id` integer NOT NULL,
	`scope_type` text NOT NULL,
	`scope_value` text NOT NULL,
	`permission` text DEFAULT 'write' NOT NULL,
	`created_at` integer DEFAULT (unixepoch()) NOT NULL,
	FOREIGN KEY (`collaborator_id`) REFERENCES `collaborator`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `idx_collaborator_grant_collaboratorId` ON `collaborator_grant` (`collaborator_id`);--> statement-breakpoint
CREATE UNIQUE INDEX `uq_collaborator_grant` ON `collaborator_grant` (`collaborator_id`,`scope_type`,`scope_value`,`permission`);--> statement-breakpoint
CREATE TABLE `project_storage_config` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`owner` text NOT NULL,
	`repo` text NOT NULL,
	`branch` text DEFAULT '' NOT NULL,
	`endpoint` text NOT NULL,
	`region` text DEFAULT 'us-east-1' NOT NULL,
	`bucket` text NOT NULL,
	`prefix` text DEFAULT '' NOT NULL,
	`force_path_style` integer DEFAULT true NOT NULL,
	`visibility` text DEFAULT 'public' NOT NULL,
	`access_key_ciphertext` text NOT NULL,
	`access_key_iv` text NOT NULL,
	`secret_key_ciphertext` text NOT NULL,
	`secret_key_iv` text NOT NULL,
	`threshold_bytes` integer DEFAULT 26214400 NOT NULL,
	`max_file_bytes` integer DEFAULT -1 NOT NULL,
	`public_base_url` text,
	`created_at` integer DEFAULT (unixepoch()) NOT NULL,
	`updated_at` integer DEFAULT (unixepoch()) NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX `uq_project_storage_owner_repo_branch` ON `project_storage_config` (lower("owner"),lower("repo"),`branch`);--> statement-breakpoint
CREATE TABLE `rate_limit` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`bucket` text NOT NULL,
	`tokens` integer NOT NULL,
	`refilled_at` integer DEFAULT (unixepoch()) NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX `rate_limit_bucket_unique` ON `rate_limit` (`bucket`);--> statement-breakpoint
CREATE UNIQUE INDEX `idx_rate_limit_bucket` ON `rate_limit` (`bucket`);--> statement-breakpoint
CREATE TABLE `storage_usage` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`owner` text NOT NULL,
	`repo` text NOT NULL,
	`branch` text DEFAULT '' NOT NULL,
	`bytes_stored` integer DEFAULT 0 NOT NULL,
	`bytes_egressed` integer DEFAULT 0 NOT NULL,
	`file_count` integer DEFAULT 0 NOT NULL,
	`last_reconciled_at` integer,
	`updated_at` integer DEFAULT (unixepoch()) NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX `uq_storage_usage_owner_repo_branch` ON `storage_usage` (lower("owner"),lower("repo"),`branch`);--> statement-breakpoint
ALTER TABLE `cache_file` ADD `referenced_at` integer;--> statement-breakpoint
CREATE INDEX `idx_cache_file_provider` ON `cache_file` (`provider`);--> statement-breakpoint
ALTER TABLE `collaborator` ADD `role` text DEFAULT 'editor' NOT NULL;