// Docs loader.
//
// Two backends, selected automatically:
//
//   FILESYSTEM (dev + Vercel build)
//     Reads from vendor/raxis-docs/ which is populated by scripts/sync-docs.mjs
//     before every dev start or Vercel build.
//
//   GITHUB API (production, when RAXIS_GITHUB_REPO is set)
//     Fetches the file tree + raw content from GitHub. Next.js caches each
//     fetch() call for REVALIDATE seconds (default 3600 = 1 hour), so content
//     refreshes in the background without a redeploy.
//     Set RAXIS_GITHUB_REPO=owner/repo (e.g. "chika5105/raxis").
//     Optional: RAXIS_GITHUB_BRANCH (default "main"), RAXIS_GITHUB_TOKEN.

import fs from "node:fs";
import path from "node:path";
import matter from "gray-matter";

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
const GITHUB_REPO = process.env.RAXIS_GITHUB_REPO; // "owner/repo"
const GITHUB_BRANCH = process.env.RAXIS_GITHUB_BRANCH ?? "main";
const GITHUB_TOKEN = process.env.RAXIS_GITHUB_TOKEN;
const FORCE_GITHUB = process.env.RAXIS_FORCE_GITHUB === "true";
const REVALIDATE = 3600; // 1 hour

// Use GitHub API when the repo is configured (production).
// In dev we always use the filesystem for speed and offline support.
const USE_GITHUB = !!GITHUB_REPO && (!IS_DEV || FORCE_GITHUB);

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

// ─── GitHub API backend ───────────────────────────────────────────────────────

async function ghFetch(url: string): Promise<Response> {
  const headers: Record<string, string> = { Accept: "application/vnd.github.v3+json" };
  if (GITHUB_TOKEN) headers["Authorization"] = `Bearer ${GITHUB_TOKEN}`;
  return fetch(url, { headers, next: { revalidate: REVALIDATE } });
}

async function fetchRaw(filePath: string): Promise<string> {
  const url = `https://raw.githubusercontent.com/${GITHUB_REPO}/${GITHUB_BRANCH}/${filePath}`;
  const res = await fetch(url, { next: { revalidate: REVALIDATE } });
  if (!res.ok) throw new Error(`GitHub raw ${res.status}: ${filePath}`);
  return res.text();
}

interface GithubTreeItem { path: string; type: string; }

async function fetchGithubTree(): Promise<GithubTreeItem[]> {
  const res = await ghFetch(
    `https://api.github.com/repos/${GITHUB_REPO}/git/trees/${GITHUB_BRANCH}?recursive=1`
  );
  if (!res.ok) throw new Error(`GitHub tree API: ${res.status}`);
  const data = await res.json();
  return (data.tree ?? []) as GithubTreeItem[];
}

async function getAllDocsFromGitHub(): Promise<DocMeta[]> {
  const tree = await fetchGithubTree();
  const mdPaths = tree
    .filter((item) => item.type === "blob" && item.path.endsWith(".md") && !isExcluded(item.path))
    .map((item) => item.path);

  // Fetch all files in parallel — Next.js deduplicates & caches each fetch.
  const results = await Promise.allSettled(
    mdPaths.map(async (filePath) => {
      const raw = await fetchRaw(filePath);
      return parseDoc(filePath, raw);
    })
  );

  const docs: DocMeta[] = [];
  for (const r of results) {
    if (r.status === "fulfilled") docs.push(r.value);
  }
  return sortDocs(docs);
}

async function getDocBySlugFromGitHub(
  slug: string[]
): Promise<{ meta: DocMeta; raw: string } | null> {
  const all = await getAllDocsFromGitHub();
  const slugPath = slug.join("/").toLowerCase();
  const meta = all.find((d) => d.slugPath === slugPath);
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
  const tree = await fetchGithubTree();
  const tomlPaths = tree
    .filter(
      (item) =>
        item.type === "blob" &&
        item.path.endsWith(".toml") &&
        item.path.startsWith(dir + "/")
    )
    .map((item) => item.path);

  const results = await Promise.allSettled(
    tomlPaths.map(async (p) => ({
      filename: p.split("/").pop()!,
      content: await fetchRaw(p),
    }))
  );

  const files: TomlFile[] = [];
  for (const r of results) {
    if (r.status === "fulfilled") files.push(r.value);
  }
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
  if (USE_GITHUB) return getAllDocsFromGitHub();
  return getAllDocsFromFS();
}

export async function getDocBySlug(
  slug: string[]
): Promise<{ meta: DocMeta; raw: string } | null> {
  if (USE_GITHUB) return getDocBySlugFromGitHub(slug);
  return getDocBySlugFromFS(slug);
}

export async function getScenarioTomlFiles(meta: DocMeta): Promise<TomlFile[]> {
  if (USE_GITHUB) return getScenarioTomlFilesFromGitHub(meta);
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
