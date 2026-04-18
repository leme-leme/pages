CREATE TABLE `cache_file` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`context` text DEFAULT 'collection' NOT NULL,
	`owner` text NOT NULL,
	`repo` text NOT NULL,
	`branch` text NOT NULL,
	`parent_path` text NOT NULL,
	`name` text NOT NULL,
	`path` text NOT NULL,
	`type` text NOT NULL,
	`content` text,
	`sha` text,
	`size` integer,
	`download_url` text,
	`commit_sha` text,
	`commit_timestamp` integer,
	`last_updated` integer NOT NULL,
	`provider` text DEFAULT 'github' NOT NULL,
	`s3_key` text
);
--> statement-breakpoint
CREATE TABLE `cache_permission` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`github_id` integer NOT NULL,
	`owner` text NOT NULL,
	`repo` text NOT NULL,
	`last_updated` integer NOT NULL
);
--> statement-breakpoint
CREATE TABLE `collaborator` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`type` text NOT NULL,
	`installation_id` integer NOT NULL,
	`owner_id` integer NOT NULL,
	`repo_id` integer,
	`owner` text NOT NULL,
	`repo` text NOT NULL,
	`branch` text,
	`email` text NOT NULL,
	`user_id` text,
	`invited_by` text NOT NULL,
	FOREIGN KEY (`user_id`) REFERENCES `user`(`id`) ON UPDATE no action ON DELETE no action,
	FOREIGN KEY (`invited_by`) REFERENCES `user`(`id`) ON UPDATE no action ON DELETE no action
);
--> statement-breakpoint
CREATE TABLE `config` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`owner` text NOT NULL,
	`repo` text NOT NULL,
	`branch` text NOT NULL,
	`sha` text NOT NULL,
	`version` text NOT NULL,
	`object` text NOT NULL
);
--> statement-breakpoint
CREATE TABLE `email_login_token` (
	`token_hash` text NOT NULL,
	`email` text NOT NULL,
	`expires_at` integer NOT NULL
);
--> statement-breakpoint
CREATE TABLE `github_installation_token` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`ciphertext` text NOT NULL,
	`iv` text NOT NULL,
	`installation_id` integer NOT NULL,
	`expires_at` integer NOT NULL
);
--> statement-breakpoint
CREATE TABLE `github_user_token` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`ciphertext` text NOT NULL,
	`iv` text NOT NULL,
	`user_id` text NOT NULL,
	FOREIGN KEY (`user_id`) REFERENCES `user`(`id`) ON UPDATE no action ON DELETE no action
);
--> statement-breakpoint
CREATE TABLE `session` (
	`id` text PRIMARY KEY NOT NULL,
	`expires_at` integer NOT NULL,
	`user_id` text NOT NULL,
	FOREIGN KEY (`user_id`) REFERENCES `user`(`id`) ON UPDATE no action ON DELETE no action
);
--> statement-breakpoint
CREATE TABLE `user` (
	`id` text PRIMARY KEY NOT NULL,
	`github_email` text,
	`github_name` text,
	`github_id` integer,
	`github_username` text,
	`email` text
);
--> statement-breakpoint
CREATE INDEX `idx_cache_file_owner_repo_branch_parentPath` ON `cache_file` (`owner`,`repo`,`branch`,`parent_path`);--> statement-breakpoint
CREATE UNIQUE INDEX `idx_cache_file_owner_repo_branch_path` ON `cache_file` (`owner`,`repo`,`branch`,`path`);--> statement-breakpoint
CREATE UNIQUE INDEX `idx_cache_permission_githubId_owner_repo` ON `cache_permission` (`github_id`,`owner`,`repo`);--> statement-breakpoint
CREATE INDEX `idx_collaborator_owner_repo_email` ON `collaborator` (`owner`,`repo`,`email`);--> statement-breakpoint
CREATE INDEX `idx_collaborator_userId` ON `collaborator` (`user_id`);--> statement-breakpoint
CREATE UNIQUE INDEX `idx_config_owner_repo_branch` ON `config` (`owner`,`repo`,`branch`);--> statement-breakpoint
CREATE UNIQUE INDEX `email_login_token_token_hash_unique` ON `email_login_token` (`token_hash`);--> statement-breakpoint
CREATE INDEX `idx_github_installation_token_installationId` ON `github_installation_token` (`installation_id`);--> statement-breakpoint
CREATE UNIQUE INDEX `idx_github_user_token_userId` ON `github_user_token` (`user_id`);--> statement-breakpoint
CREATE INDEX `idx_session_userId` ON `session` (`user_id`);--> statement-breakpoint
CREATE UNIQUE INDEX `user_github_id_unique` ON `user` (`github_id`);--> statement-breakpoint
CREATE UNIQUE INDEX `user_email_unique` ON `user` (`email`);