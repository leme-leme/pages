CREATE TABLE `analytics_rollup` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`date` text NOT NULL,
	`owner` text DEFAULT '' NOT NULL,
	`repo` text DEFAULT '' NOT NULL,
	`event_type` text NOT NULL,
	`count` integer DEFAULT 0 NOT NULL,
	`bytes` integer DEFAULT 0 NOT NULL,
	`unique_actors` integer DEFAULT 0 NOT NULL,
	`created_at` integer DEFAULT (unixepoch()) NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX `uq_analytics_rollup` ON `analytics_rollup` (`date`,`owner`,`repo`,`event_type`);--> statement-breakpoint
CREATE INDEX `idx_analytics_rollup_date` ON `analytics_rollup` (`date`);--> statement-breakpoint
CREATE TABLE `project_analytics_config` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`owner` text NOT NULL,
	`repo` text NOT NULL,
	`branch` text DEFAULT '' NOT NULL,
	`ga4_measurement_id` text,
	`plausible_domain` text,
	`plausible_api_host` text,
	`cf_beacon_token` text,
	`require_consent` integer DEFAULT true NOT NULL,
	`honor_dnt` integer DEFAULT true NOT NULL,
	`created_at` integer DEFAULT (unixepoch()) NOT NULL,
	`updated_at` integer DEFAULT (unixepoch()) NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX `uq_project_analytics_owner_repo_branch` ON `project_analytics_config` (lower("owner"),lower("repo"),`branch`);