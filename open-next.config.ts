import { defineCloudflareConfig } from "@opennextjs/cloudflare";

export default defineCloudflareConfig({
  override: {
    wrapper: "cloudflare-node",
  },
});
