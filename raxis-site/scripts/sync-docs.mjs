#!/usr/bin/env node
// Mirror the raxis docs into ./vendor/raxis-docs/ before Next.js builds.
//
// Resolution order:
//   1. RAXIS_REPO_PATH=/abs/or/relative/path  → copy from local checkout
//   2. RAXIS_REPO_URL=https://...git          → shallow clone into vendor/_raxis-clone, then copy
//   3. existing vendor/raxis-docs/            → leave it alone (last good copy)
//   4. nothing                                → emit a tiny placeholder so the site still builds
//
// Only files matched by INCLUDE_GLOBS are copied. We deliberately exclude
// every Rust source file, Cargo lock files, build artifacts, and any path
// containing keys, certs, or secrets.
//
// This script must be deterministic so Vercel cache hashing is sensible.

import fs from "node:fs";
import path from "node:path";
import { execSync } from "node:child_process";
import url from "node:url";

const __filename = url.fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT = path.resolve(__dirname, "..");
const DEST = path.join(ROOT, "vendor", "raxis-docs");
const CLONE_DIR = path.join(ROOT, "vendor", "_raxis-clone");

const ALLOWED_EXTENSIONS = new Set([".md", ".mdx"]);
// TOML scenario config files that are safe to vendor (example configs, not secrets).
const SCENARIO_TOML_DIR = "guides/scenarios";
const SKIP_DIRS = new Set([
  "node_modules",
  ".git",
  ".next",
  "target",
  "dist",
  "build",
  ".vercel",
  ".turbo",
  "coverage",
]);
const SKIP_FILE_PATTERNS = [/\.pem$/i, /\.key$/i, /\.crt$/i, /credentials?/i, /secret/i];

function log(msg) {
  process.stdout.write(`[sync-docs] ${msg}\n`);
}

function rmRecursive(p) {
  if (!fs.existsSync(p)) return;
  fs.rmSync(p, { recursive: true, force: true });
}

function isMarkdown(file) {
  return ALLOWED_EXTENSIONS.has(path.extname(file).toLowerCase());
}

function shouldSkipFile(name) {
  return SKIP_FILE_PATTERNS.some((re) => re.test(name));
}

function ensureDir(p) {
  fs.mkdirSync(p, { recursive: true });
}

function isScenarioToml(relPath) {
  // e.g. "guides/scenarios/01-hello-world/plan.toml"
  const norm = relPath.split(path.sep).join("/").toLowerCase();
  return (
    norm.startsWith(SCENARIO_TOML_DIR + "/") &&
    path.extname(relPath).toLowerCase() === ".toml"
  );
}

function copyMarkdownTree(src, dst) {
  let count = 0;
  if (!fs.existsSync(src)) return 0;
  const stack = [src];
  while (stack.length) {
    const current = stack.pop();
    let entries;
    try {
      entries = fs.readdirSync(current, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      const abs = path.join(current, entry.name);
      const rel = path.relative(src, abs);
      if (entry.isDirectory()) {
        if (SKIP_DIRS.has(entry.name)) continue;
        stack.push(abs);
        continue;
      }
      if (!entry.isFile()) continue;
      // Copy markdown files and TOML scenario configs.
      const isToml = isScenarioToml(rel);
      if (!isToml) {
        if (!isMarkdown(entry.name)) continue;
        if (shouldSkipFile(entry.name)) continue;
      }
      const target = path.join(dst, rel);
      ensureDir(path.dirname(target));
      fs.copyFileSync(abs, target);
      count++;
    }
  }
  return count;
}

function shallowClone(repoUrl) {
  rmRecursive(CLONE_DIR);
  ensureDir(path.dirname(CLONE_DIR));
  log(`shallow-cloning ${repoUrl} → ${path.relative(ROOT, CLONE_DIR)}`);
  execSync(`git clone --depth 1 --filter=blob:limit=2m ${JSON.stringify(repoUrl)} ${JSON.stringify(CLONE_DIR)}`, {
    stdio: "inherit",
    env: { ...process.env, GIT_TERMINAL_PROMPT: "0" },
  });
  return CLONE_DIR;
}

function writePlaceholder() {
  ensureDir(DEST);
  const file = path.join(DEST, "README.md");
  fs.writeFileSync(
    file,
    [
      "# RAXIS docs are not vendored yet",
      "",
      "Set the `RAXIS_REPO_PATH` env var to a local raxis checkout, or set",
      "`RAXIS_REPO_URL` to a public git URL, then re-run the build.",
      "",
      "    RAXIS_REPO_PATH=../raxis npm run build",
      "    # or",
      "    RAXIS_REPO_URL=https://github.com/cjinanwa/raxis.git npm run build",
      "",
      "The `scripts/sync-docs.mjs` step copies every `.md` file from that",
      "source into `vendor/raxis-docs/`, and the rest of the site renders",
      "from there at build time.",
    ].join("\n"),
    "utf8",
  );
  log("wrote placeholder README.md");
}

function main() {
  // Auto-detect the sibling raxis/ directory when no env var is set.
  let repoPath = process.env.RAXIS_REPO_PATH;
  const repoUrl = process.env.RAXIS_REPO_URL;
  if (!repoPath && !repoUrl) {
    const candidate = path.resolve(ROOT, "..", "raxis");
    if (fs.existsSync(candidate)) {
      log(`auto-detected local raxis repo at ${candidate}`);
      repoPath = candidate;
    }
  }

  // Always start from a clean destination so removed source files don't linger.
  if (repoPath || repoUrl) {
    rmRecursive(DEST);
    ensureDir(DEST);
  }

  if (repoPath) {
    const abs = path.resolve(ROOT, repoPath);
    if (!fs.existsSync(abs)) {
      log(`RAXIS_REPO_PATH=${repoPath} resolves to ${abs} which does not exist`);
      process.exit(1);
    }
    log(`mirroring from ${abs}`);
    const n = copyMarkdownTree(abs, DEST);
    log(`copied ${n} markdown files into ${path.relative(ROOT, DEST)}`);
    return;
  }

  if (repoUrl) {
    const cloned = shallowClone(repoUrl);
    const n = copyMarkdownTree(cloned, DEST);
    log(`copied ${n} markdown files into ${path.relative(ROOT, DEST)}`);
    rmRecursive(CLONE_DIR);
    return;
  }

  if (fs.existsSync(DEST) && fs.readdirSync(DEST).length > 0) {
    log(`no env var set; reusing existing ${path.relative(ROOT, DEST)}`);
    return;
  }

  log("no RAXIS_REPO_PATH or RAXIS_REPO_URL set, and no vendor/raxis-docs to fall back on");
  writePlaceholder();
}

try {
  main();
} catch (err) {
  console.error("[sync-docs] failed:", err);
  process.exit(1);
}
