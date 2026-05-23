// Docs loader.
//
// Docs can come from either the build-time mirror or the public GitHub API:
//
//   FILESYSTEM (dev + Vercel build)
//     Reads from vendor/raxis-docs/ which is populated by scripts/sync-docs.mjs
//     before every dev start or Vercel build.
//
//   ANONYMOUS GITHUB API (production, when RAXIS_GITHUB_REPO is set)
//     Builds a cached manifest from the public repo without any token or auth
//     header. Raw files are cached as separate entries so Vercel's cache item
//     size limit is not hit. The GitHub data revalidates hourly; the refresh
//     route can also be called by a scheduler to warm the bundle. If GitHub is
//     unavailable, the filesystem mirror remains the static fallback.

import fs from "node:fs";
import path from "node:path";
import matter from "gray-matter";
import { revalidateTag, unstable_cache } from "next/cache";

export type DocCategory =
  | "Overview"
  | "Concepts"
  | "Specs"
  | "Guides"
  | "Scenarios"
  | "Perspectives";

export interface DocMeta {
  slug: string[];
  slugPath: string;
  relativePath: string;
  title: string;
  category: DocCategory;
  subgroup?: string;
  snippet: string;
  headings: Array<{ depth: 2 | 3; text: string; id: string }>;
  order: number;
}

export interface DocFull extends DocMeta {
  html: string;
  plain: string;
}

export interface TomlFile {
  filename: string;
  content: string;
}

// ─── Config ──────────────────────────────────────────────────────────────────

const DOCS_DIR = path.join(process.cwd(), "vendor", "raxis-docs");
const IS_DEV = process.env.NODE_ENV === "development";
const IS_SITE_BUILD = process.env.RAXIS_SITE_BUILD === "1";
const GITHUB_REPO = process.env.RAXIS_GITHUB_REPO; // "owner/repo"
const GITHUB_BRANCH = process.env.RAXIS_GITHUB_BRANCH ?? "main";
const GITHUB_PREFIX = normalizeGithubPrefix(process.env.RAXIS_GITHUB_PREFIX);
const REVALIDATE = 3600; // 1 hour
const FORCE_GITHUB = process.env.RAXIS_FORCE_GITHUB === "true";
const GITHUB_FETCH_TIMEOUT_MS = 15_000;
const GITHUB_DOCS_CACHE_TAG = "raxis-github-docs-bundle";
const GITHUB_RAW_CONCURRENCY = boundedInt(
  process.env.RAXIS_GITHUB_RAW_CONCURRENCY,
  1,
  12,
  6
);

// Use anonymous GitHub API when configured in production. In dev, prefer the
// filesystem mirror unless explicitly forced for debugging.
const USE_GITHUB = !!GITHUB_REPO && !IS_SITE_BUILD && (!IS_DEV || FORCE_GITHUB);

// ─── Exclusion rules ─────────────────────────────────────────────────────────

const EXCLUDE_PREFIXES = [
  ".github/",
  "crates/store/migrations",
  "crates/store/migrations/",
  "release",
  "release/",
  "images",
  "images/",
  "installer",
  "installer/",
];
const EXCLUDE_BASENAME_PATTERNS: RegExp[] = [
  /^_/,
  /^changelog\.md$/i,
  /^license\.md$/i,
  /^contributing\.md$/i,
];

function isExcluded(rel: string): boolean {
  const segs = rel.split("/");
  const norm = segs.join("/").toLowerCase();
  for (const p of EXCLUDE_PREFIXES) {
    if (norm === p.replace(/\/$/, "") + ".md") return true;
    if (norm.startsWith(p.toLowerCase())) return true;
  }
  for (const seg of segs) {
    if (seg.startsWith("_")) return true;
  }
  const base = rel.split("/").pop() ?? "";
  for (const re of EXCLUDE_BASENAME_PATTERNS) if (re.test(base)) return true;
  return false;
}

// ─── Shared parsing helpers ───────────────────────────────────────────────────

function pathToSlug(relPath: string): string[] {
  const norm = relPath.split(path.sep).join("/");
  let withoutExt = norm.replace(/\.md$/i, "");
  withoutExt = withoutExt.replace(/\/README$/i, "");
  if (withoutExt === "README") withoutExt = "readme";
  return withoutExt.split("/").map((s) => s.toLowerCase());
}

function categorize(rel: string): { category: DocCategory; subgroup?: string } {
  const norm = rel.split(path.sep).join("/").toLowerCase();
  if (norm.startsWith("raxis-concepts/")) return { category: "Concepts" };
  if (norm.startsWith("specs/v1/")) return { category: "Specs", subgroup: "v1" };
  if (norm.startsWith("specs/v2/")) return { category: "Specs", subgroup: "v2" };
  if (norm.startsWith("specs/v3/")) return { category: "Specs", subgroup: "v3" };
  if (norm.startsWith("specs/")) return { category: "Specs", subgroup: "Foundations" };
  if (norm.startsWith("guides/scenarios/")) return { category: "Scenarios" };
  if (norm.startsWith("guides/patterns/")) return { category: "Guides", subgroup: "Patterns" };
  if (norm.startsWith("guides/security/")) return { category: "Guides", subgroup: "Security" };
  if (norm.startsWith("guides/")) return { category: "Guides", subgroup: "Setup" };
  if (norm.startsWith("perspectives/")) return { category: "Perspectives" };
  return { category: "Overview" };
}

function extractTitle(filename: string, frontmatter: Record<string, unknown>, body: string): string {
  if (frontmatter.title && typeof frontmatter.title === "string") return frontmatter.title;
  const h1 = /^#\s+(.+)$/m.exec(body);
  if (h1) return h1[1].replace(/[`*_]/g, "").trim();
  const base = filename.replace(/\.md$/i, "").replace(/^README$/i, "Overview");
  return base.replace(/[-_]+/g, " ").replace(/\b\w/g, (m) => m.toUpperCase());
}

function makeSnippet(text: string, limit = 220): string {
  const stripped = text
    .replace(/^#+\s+.+$/gm, "")
    .replace(/```[\s\S]*?```/g, "")
    .replace(/[*_`>~|#-]+/g, " ")
    .replace(/\s+/g, " ")
    .trim();
  if (stripped.length <= limit) return stripped;
  return stripped.slice(0, limit).replace(/\s+\S*$/, "") + "…";
}

function extractHeadings(body: string): Array<{ depth: 2 | 3; text: string; id: string }> {
  const out: Array<{ depth: 2 | 3; text: string; id: string }> = [];
  const lines = body.split("\n");
  let inFence = false;
  for (const line of lines) {
    if (/^```/.test(line)) { inFence = !inFence; continue; }
    if (inFence) continue;
    const m = /^(#{2,3})\s+(.+?)\s*$/.exec(line);
    if (!m) continue;
    const depth = m[1].length === 2 ? 2 : 3;
    const text = m[2].replace(/[`*_]/g, "").trim();
    const id = text.toLowerCase().replace(/[^\p{L}\p{N}\s-]+/gu, "").trim().replace(/\s+/g, "-");
    out.push({ depth: depth as 2 | 3, text, id });
  }
  return out;
}

function orderFor(category: DocCategory, slugPath: string, title: string): number {
  if (category === "Concepts" || category === "Scenarios") {
    const m = /\/(\d+)-/.exec(slugPath);
    if (m) return parseInt(m[1], 10);
  }
  if (category === "Overview") {
    if (/\/?readme$/i.test(slugPath)) return 0;
    if (/positioning$/i.test(slugPath)) return 1;
  }
  return 1000 + (title.charCodeAt(0) || 0);
}

function parseDoc(relPath: string, raw: string): DocMeta {
  const parsed = matter(raw);
  const body = parsed.content;
  const slug = pathToSlug(relPath);
  const slugPath = slug.join("/");
  const filename = relPath.split("/").pop() ?? relPath;
  const title = extractTitle(filename, parsed.data ?? {}, body);
  const { category, subgroup } = categorize(relPath);
  return {
    slug,
    slugPath,
    relativePath: relPath,
    title,
    category,
    subgroup,
    snippet: makeSnippet(body),
    headings: extractHeadings(body),
    order: orderFor(category, slugPath, title),
  };
}

function sortDocs(docs: DocMeta[]): DocMeta[] {
  return docs.sort((a, b) => {
    if (a.category !== b.category) return a.category.localeCompare(b.category);
    if ((a.subgroup ?? "") !== (b.subgroup ?? ""))
      return (a.subgroup ?? "").localeCompare(b.subgroup ?? "");
    if (a.order !== b.order) return a.order - b.order;
    return a.title.localeCompare(b.title);
  });
}

// ─── Filesystem backend ───────────────────────────────────────────────────────

function exists(p: string): boolean {
  try { fs.accessSync(p); return true; } catch { return false; }
}

function safeReadDirRecursive(root: string): string[] {
  const out: string[] = [];
  if (!exists(root)) return out;
  const SKIP = new Set(["node_modules", ".git", "target", "dist", "build", ".next"]);
  const stack: string[] = [root];
  while (stack.length) {
    const dir = stack.pop()!;
    let entries: fs.Dirent[];
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { continue; }
    for (const e of entries) {
      const full = path.join(dir, e.name);
      if (e.isDirectory()) { if (!SKIP.has(e.name)) stack.push(full); }
      else if (e.isFile() && e.name.toLowerCase().endsWith(".md")) out.push(full);
    }
  }
  return out;
}

let _fsCache: DocMeta[] | null = null;

function getAllDocsFromFS(): DocMeta[] {
  if (_fsCache && !IS_DEV) return _fsCache;
  if (!exists(DOCS_DIR)) { _fsCache = []; return []; }
  const files = safeReadDirRecursive(DOCS_DIR);
  const docs: DocMeta[] = [];
  for (const abs of files) {
    const rel = path.relative(DOCS_DIR, abs).split(path.sep).join("/");
    if (isExcluded(rel)) continue;
    let raw: string;
    try { raw = fs.readFileSync(abs, "utf8"); } catch { continue; }
    docs.push(parseDoc(rel, raw));
  }
  _fsCache = sortDocs(docs);
  return _fsCache;
}

function getDocBySlugFromFS(slug: string[]): { meta: DocMeta; raw: string } | null {
  const slugPath = slug.join("/").toLowerCase();
  const meta = getAllDocsFromFS().find((d) => d.slugPath === slugPath);
  if (!meta) return null;
  const abs = path.join(DOCS_DIR, meta.relativePath);
  try { return { meta, raw: fs.readFileSync(abs, "utf8") }; } catch { return null; }
}

function getScenarioTomlFilesFromFS(meta: DocMeta): TomlFile[] {
  if (meta.category !== "Scenarios") return [];
  const dir = path.join(DOCS_DIR, path.dirname(meta.relativePath));
  if (!exists(dir)) return [];
  let entries: fs.Dirent[];
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return []; }
  const files: TomlFile[] = [];
  for (const e of entries) {
    if (!e.isFile() || path.extname(e.name).toLowerCase() !== ".toml") continue;
    try {
      files.push({ filename: e.name, content: fs.readFileSync(path.join(dir, e.name), "utf8") });
    } catch { /* skip */ }
  }
  const ORDER = ["plan.toml", "policy.toml", "credential.toml"];
  return files.sort((a, b) => {
    const ai = ORDER.indexOf(a.filename), bi = ORDER.indexOf(b.filename);
    if (ai !== -1 && bi !== -1) return ai - bi;
    if (ai !== -1) return -1; if (bi !== -1) return 1;
    return a.filename.localeCompare(b.filename);
  });
}

// ─── Anonymous GitHub API backend ────────────────────────────────────────────

function boundedInt(
  value: string | undefined,
  min: number,
  max: number,
  fallback: number
): number {
  const parsed = Number.parseInt(value ?? "", 10);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(max, Math.max(min, parsed));
}

function normalizeGithubPrefix(prefix: string | undefined): string {
  return (prefix ?? "").trim().replace(/^\/+|\/+$/g, "");
}

function stripGithubPrefix(repoPath: string): string | null {
  if (!GITHUB_PREFIX) return repoPath;
  if (repoPath === GITHUB_PREFIX) return "";
  if (!repoPath.startsWith(GITHUB_PREFIX + "/")) return null;
  return repoPath.slice(GITHUB_PREFIX.length + 1);
}

function withGithubPrefix(relPath: string): string {
  const clean = relPath.replace(/^\/+/, "");
  return GITHUB_PREFIX ? `${GITHUB_PREFIX}/${clean}` : clean;
}

function encodeGithubPath(repoPath: string): string {
  return repoPath.split("/").map(encodeURIComponent).join("/");
}

async function ghFetch(url: string): Promise<Response> {
  return fetchWithRetry(url, {
    headers: { Accept: "application/vnd.github.v3+json" },
    next: { revalidate: REVALIDATE, tags: [GITHUB_DOCS_CACHE_TAG] },
  });
}

async function fetchRaw(filePath: string): Promise<string> {
  const repoPath = encodeGithubPath(withGithubPrefix(filePath));
  const url = `https://raw.githubusercontent.com/${GITHUB_REPO}/${GITHUB_BRANCH}/${repoPath}`;
  const res = await fetchWithRetry(url, {
    next: { revalidate: REVALIDATE, tags: [GITHUB_DOCS_CACHE_TAG] },
  });
  if (!res.ok) throw new Error(`GitHub raw ${res.status}: ${filePath}`);
  return res.text();
}

async function fetchWithRetry(
  url: string,
  init: RequestInit & { next?: { revalidate?: number; tags?: string[] } },
  attempts = 3
): Promise<Response> {
  let lastErr: unknown;
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), GITHUB_FETCH_TIMEOUT_MS);
    try {
      const res = await fetch(url, { ...init, signal: controller.signal });
      clearTimeout(timeout);
      if (res.ok || res.status < 500 || attempt === attempts - 1) return res;
      lastErr = new Error(`GitHub fetch ${res.status}: ${url}`);
    } catch (err) {
      clearTimeout(timeout);
      lastErr = err;
      if (attempt === attempts - 1) break;
    }
    await new Promise((resolve) => setTimeout(resolve, 250 * (attempt + 1)));
  }
  throw lastErr instanceof Error ? lastErr : new Error(`GitHub fetch failed: ${url}`);
}

async function mapWithConcurrency<T, U>(
  items: T[],
  limit: number,
  fn: (item: T, index: number) => Promise<U>
): Promise<U[]> {
  const out = new Array<U>(items.length);
  let next = 0;
  const workers = Array.from(
    { length: Math.min(limit, items.length) },
    async () => {
      while (next < items.length) {
        const index = next;
        next += 1;
        out[index] = await fn(items[index], index);
      }
    }
  );
  await Promise.all(workers);
  return out;
}

interface GithubTreeItem { path: string; type: string; }

interface GithubDocsManifest {
  fetchedAt: string;
  docs: DocMeta[];
}

async function fetchGithubTree(): Promise<GithubTreeItem[]> {
  const res = await ghFetch(
    `https://api.github.com/repos/${GITHUB_REPO}/git/trees/${GITHUB_BRANCH}?recursive=1`
  );
  if (!res.ok) throw new Error(`GitHub tree API: ${res.status}`);
  const data = await res.json();
  return (data.tree ?? []) as GithubTreeItem[];
}

async function fetchGitHubDocsManifestUncached(): Promise<GithubDocsManifest> {
  const tree = await fetchGithubTree();
  const mdPaths = tree
    .filter((item) => item.type === "blob")
    .map((item) => stripGithubPrefix(item.path))
    .filter((relPath): relPath is string => !!relPath)
    .filter((relPath) => relPath.endsWith(".md") && !isExcluded(relPath));

  const docs = await mapWithConcurrency(
    mdPaths,
    GITHUB_RAW_CONCURRENCY,
    async (filePath) => {
      const raw = await fetchRaw(filePath);
      return parseDoc(filePath, raw);
    }
  );

  return {
    fetchedAt: new Date().toISOString(),
    docs: sortDocs(docs),
  };
}

const getCachedGitHubDocsManifest = unstable_cache(
  fetchGitHubDocsManifestUncached,
  ["raxis-github-docs-manifest", GITHUB_REPO ?? "", GITHUB_BRANCH, GITHUB_PREFIX],
  {
    revalidate: REVALIDATE,
    tags: [GITHUB_DOCS_CACHE_TAG],
  }
);

async function getGitHubDocsManifest(): Promise<GithubDocsManifest> {
  return getCachedGitHubDocsManifest();
}

async function getGitHubTomlPaths(): Promise<string[]> {
  const tree = await fetchGithubTree();
  return tree
    .filter((item) => item.type === "blob")
    .map((item) => stripGithubPrefix(item.path))
    .filter((relPath): relPath is string => !!relPath)
    .filter((relPath) => relPath.endsWith(".toml") && !isExcluded(relPath));
}

export async function refreshGitHubDocsBundle(): Promise<GithubDocsManifest> {
  revalidateTag(GITHUB_DOCS_CACHE_TAG);
  const manifest = await getGitHubDocsManifest();
  const tomlPaths = await getGitHubTomlPaths();
  await mapWithConcurrency(tomlPaths, GITHUB_RAW_CONCURRENCY, fetchRaw);
  return manifest;
}

async function getAllDocsFromGitHub(): Promise<DocMeta[]> {
  return (await getGitHubDocsManifest()).docs;
}

async function getDocBySlugFromGitHub(
  slug: string[]
): Promise<{ meta: DocMeta; raw: string } | null> {
  const manifest = await getGitHubDocsManifest();
  const slugPath = slug.join("/").toLowerCase();
  const meta = manifest.docs.find((d) => d.slugPath === slugPath);
  if (!meta) return null;
  try {
    const raw = await fetchRaw(meta.relativePath);
    return { meta, raw };
  } catch {
    return null;
  }
}

async function getScenarioTomlFilesFromGitHub(meta: DocMeta): Promise<TomlFile[]> {
  if (meta.category !== "Scenarios") return [];
  const dir = meta.relativePath.split("/").slice(0, -1).join("/");
  const tomlPaths = (await getGitHubTomlPaths())
    .filter(
      (relPath) => relPath.startsWith(dir + "/")
    );

  const files = await mapWithConcurrency(
    tomlPaths,
    GITHUB_RAW_CONCURRENCY,
    async (relPath) => ({
      filename: relPath.split("/").pop()!,
      content: await fetchRaw(relPath),
    })
  );
  const ORDER = ["plan.toml", "policy.toml", "credential.toml"];
  return files.sort((a, b) => {
    const ai = ORDER.indexOf(a.filename), bi = ORDER.indexOf(b.filename);
    if (ai !== -1 && bi !== -1) return ai - bi;
    if (ai !== -1) return -1; if (bi !== -1) return 1;
    return a.filename.localeCompare(b.filename);
  });
}

// ─── Public API (always async) ────────────────────────────────────────────────

export async function getAllDocs(): Promise<DocMeta[]> {
  if (USE_GITHUB) {
    try {
      return await getAllDocsFromGitHub();
    } catch (err) {
      console.warn("[docs] anonymous GitHub API unavailable, falling back to bundled copy:", err);
      return getAllDocsFromFS();
    }
  }
  return getAllDocsFromFS();
}

export async function getDocBySlug(
  slug: string[]
): Promise<{ meta: DocMeta; raw: string } | null> {
  if (USE_GITHUB) {
    try {
      return await getDocBySlugFromGitHub(slug);
    } catch (err) {
      console.warn("[docs] anonymous GitHub API unavailable, falling back to bundled copy:", err);
      return getDocBySlugFromFS(slug);
    }
  }
  return getDocBySlugFromFS(slug);
}

export async function getScenarioTomlFiles(meta: DocMeta): Promise<TomlFile[]> {
  if (USE_GITHUB) {
    try {
      return await getScenarioTomlFilesFromGitHub(meta);
    } catch (err) {
      console.warn("[docs] anonymous GitHub API unavailable, falling back to bundled copy:", err);
      return getScenarioTomlFilesFromFS(meta);
    }
  }
  return getScenarioTomlFilesFromFS(meta);
}

// ─── Category helpers ─────────────────────────────────────────────────────────

export interface DocsByCategory {
  category: DocCategory;
  groups: Array<{ subgroup: string | undefined; docs: DocMeta[] }>;
}

const CATEGORY_ORDER: DocCategory[] = [
  "Overview", "Concepts", "Specs", "Guides", "Scenarios", "Perspectives",
];

export async function getDocsByCategory(): Promise<DocsByCategory[]> {
  const all = await getAllDocs();
  const grouped: Record<DocCategory, Map<string | undefined, DocMeta[]>> = {
    Overview: new Map(), Concepts: new Map(), Specs: new Map(),
    Guides: new Map(), Scenarios: new Map(), Perspectives: new Map(),
  };
  for (const d of all) {
    const m = grouped[d.category];
    if (!m.has(d.subgroup)) m.set(d.subgroup, []);
    m.get(d.subgroup)!.push(d);
  }
  const out: DocsByCategory[] = [];
  for (const cat of CATEGORY_ORDER) {
    const m = grouped[cat];
    if (m.size === 0) continue;
    const groups = Array.from(m.entries()).map(([subgroup, docs]) => ({ subgroup, docs }));
    if (cat === "Specs") {
      const want = ["Foundations", "v1", "v2", "v3"];
      groups.sort((a, b) => {
        const ai = a.subgroup ? want.indexOf(a.subgroup) : -1;
        const bi = b.subgroup ? want.indexOf(b.subgroup) : -1;
        return ai - bi;
      });
    } else {
      groups.sort((a, b) => (a.subgroup ?? "").localeCompare(b.subgroup ?? ""));
    }
    out.push({ category: cat, groups });
  }
  return out;
}

export function categoryDescription(c: DocCategory): string {
  switch (c) {
    case "Overview":
      return "Top-level project documents — README, positioning, kernel feedback flows, witness configuration.";
    case "Concepts":
      return "Operator-facing guides for every core mechanism: claims & gates, intent admission, credential proxies, delegations, lanes & budgets, the audit chain, escalations, sessions, policy, v2 orchestration.";
    case "Specs":
      return "The normative spec tree. v1 (the local, single-operator MVP), v2 (multi-agent coordination, microVM isolation), v3 (design intent, gated behind dedicated gap specs).";
    case "Guides":
      return "Operator workflows: setup, security threat models, multi-environment deployment, integration patterns (single executor + reviewer, panel review, structured debate).";
    case "Scenarios":
      return "Reproducible end-to-end recipes — from a one-file hello world to a full feature shipment with parallel decomposition, panel review, mechanical witnesses, and operator-approved integration merge.";
    case "Perspectives":
      return "The origin story, the steel-man critique against RAXIS, the structured response, and the conceptual analysis behind the paradigm.";
  }
}
