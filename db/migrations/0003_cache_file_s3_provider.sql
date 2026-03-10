ALTER TABLE "cache_file" ADD COLUMN IF NOT EXISTS "provider" text NOT NULL DEFAULT 'github';
ALTER TABLE "cache_file" ADD COLUMN IF NOT EXISTS "s3_key" text;
