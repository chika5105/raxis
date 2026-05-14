#!/usr/bin/env node
// Dev-mode watcher: syncs docs + rebuilds search index on source changes.
// Run alongside `next dev` — the package.json dev script does this automatically.

import fs from "node:fs";
import path from "node:path";
import { execSync } from "node:child_process";
import url from "node:url";

const __filename = url.fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT = path.resolve(__dirname, "..");

function log(msg) {
  process.stdout.write(`[watch-docs] ${msg}\n`);
}

function runSync() {
  try {
    execSync("node scripts/sync-docs.mjs && node scripts/build-search-index.mjs", {
      cwd: ROOT,
      stdio: "inherit",
    });
  } catch (err) {
    log(`sync failed: ${err.message}`);
  }
}

// Resolve the source directory to watch (same logic as sync-docs.mjs).
function resolveSourceDir() {
  const repoPath = process.env.RAXIS_REPO_PATH;
  if (repoPath) return path.resolve(ROOT, repoPath);
  const candidate = path.resolve(ROOT, "..", "raxis");
  if (fs.existsSync(candidate)) return candidate;
  return null;
}

// Initial sync on startup.
log("initial sync…");
runSync();

const sourceDir = resolveSourceDir();
if (!sourceDir) {
  log("no local raxis repo found — watching disabled (using vendored snapshot)");
  process.exit(0);
}

log(`watching ${sourceDir} for changes…`);

let debounceTimer = null;
function scheduleSync() {
  if (debounceTimer) clearTimeout(debounceTimer);
  debounceTimer = setTimeout(() => {
    log("change detected, re-syncing…");
    runSync();
    log("ready");
  }, 300);
}

try {
  fs.watch(sourceDir, { recursive: true }, (_event, filename) => {
    if (!filename) return;
    // Only react to markdown and TOML files.
    const ext = path.extname(filename).toLowerCase();
    if (ext === ".md" || ext === ".mdx" || ext === ".toml") {
      scheduleSync();
    }
  });
} catch (err) {
  // fs.watch recursive is not supported everywhere — fall back silently.
  log(`watch not available: ${err.message}`);
}
