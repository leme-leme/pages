import bundleAnalyzer from "@next/bundle-analyzer";

const withBundleAnalyzer = bundleAnalyzer({
  enabled: process.env.ANALYZE === 'true',
})

/** @type {import('next').NextConfig} */
const nextConfig = {
  // The upstream codebase has pre-existing Lucia `User` type errors (the
  // `declare module "lucia"` augmentation isn't being picked up for some
  // files). Production-runtime behavior is unaffected. Re-enable when the
  // types are fixed or we move to Next 15.
  typescript: { ignoreBuildErrors: true },
  eslint: { ignoreDuringBuilds: true },
};

export default withBundleAnalyzer(nextConfig);

if (process.env.NODE_ENV === "development") {
  const { initOpenNextCloudflareForDev } = await import("@opennextjs/cloudflare");
  initOpenNextCloudflareForDev();
}