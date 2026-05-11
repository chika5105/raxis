import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // Pin the workspace root so Next does not climb up to a parent lockfile.
  outputFileTracingRoot: __dirname,
  // The docs loader reads markdown files from the local filesystem at build time
  // (when `RAXIS_REPO_PATH` is set) or from the bundled mirror under
  // `vendor/raxis-docs`. No runtime filesystem access — so this site builds and
  // ships statically on Vercel.
  typedRoutes: false,
};

export default nextConfig;
