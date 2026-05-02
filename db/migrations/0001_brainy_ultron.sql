ALTER TABLE `cache_file` ADD `provider` text DEFAULT 'github' NOT NULL;--> statement-breakpoint
ALTER TABLE `cache_file` ADD `s3_key` text;