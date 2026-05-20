import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // Pin the workspace root so Next does not climb up to a parent lockfile.
  outputFileTracingRoot: __dirname,
  // Bundle the vendored docs mirror into the Vercel deployment so that the
  // filesystem backend is available as a fallback when the GitHub API is down.
  // sync-docs.mjs populates vendor/raxis-docs/ during `prebuild`.
  outputFileTracingIncludes: {
    "/(.*)/": ["./vendor/raxis-docs/**/*"],
  },
  allowedDevOrigins: ["127.0.0.1"],
  typedRoutes: false,
};

export default nextConfig;
