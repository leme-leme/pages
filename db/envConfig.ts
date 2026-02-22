// Load .env for local development
// On Cloudflare, env vars come from wrangler.toml / dashboard
if (typeof process !== "undefined" && process.env) {
  try {
    const { loadEnvConfig } = require("@next/env");
    loadEnvConfig(process.cwd());
  } catch {
    // @next/env not available in edge runtime
  }
}
