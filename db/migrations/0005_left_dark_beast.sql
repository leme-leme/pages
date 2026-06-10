CREATE TABLE `scheduled_job` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`owner` text NOT NULL,
	`repo` text NOT NULL,
	`branch` text NOT NULL,
	`action` text NOT NULL,
	`target_path` text NOT NULL,
	`schema_name` text NOT NULL,
	`payload` text,
	`is_batch` integer DEFAULT false NOT NULL,
	`schedule_kind` text NOT NULL,
	`cron_expr` text,
	`timezone` text DEFAULT 'UTC' NOT NULL,
	`run_at` integer NOT NULL,
	`status` text DEFAULT 'pending' NOT NULL,
	`attempts` integer DEFAULT 0 NOT NULL,
	`max_attempts` integer DEFAULT 3 NOT NULL,
	`last_run_at` integer,
	`last_error` text,
	`locked_at` integer,
	`created_by_user_id` text,
	`created_by_email` text,
	`created_at` integer DEFAULT (unixepoch()) NOT NULL,
	`updated_at` integer DEFAULT (unixepoch()) NOT NULL,
	FOREIGN KEY (`created_by_user_id`) REFERENCES `user`(`id`) ON UPDATE no action ON DELETE set null
);
--> statement-breakpoint
CREATE INDEX `idx_scheduled_job_status_runAt` ON `scheduled_job` (`status`,`run_at`);--> statement-breakpoint
CREATE INDEX `idx_scheduled_job_owner_repo_branch` ON `scheduled_job` (`owner`,`repo`,`branch`);