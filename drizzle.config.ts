import { defineConfig } from "drizzle-kit";

export default defineConfig({
  dialect: "sqlite",
  driver: "d1-http",
  schema: "./db/schema.ts",
  out: "./db/migrations",
  strict: true,
  verbose: true,
});
