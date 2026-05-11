// Docs loader.
//
// Reads markdown files from a local mirror at `vendor/raxis-docs/`.
// The mirror is populated at `prebuild` time by `scripts/sync-docs.mjs`,
// which copies from `RAXIS_REPO_PATH` (preferred) or shallow-clones
// `RAXIS_REPO_URL` (fallback for Vercel). Either way, by the time this
// module runs, all source markdown is on the local filesystem and the
// rendered site has no runtime filesystem dependency.

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
  /** URL slug, e.g. ["raxis-concepts", "01-claims-and-gates"]. */
  slug: string[];
  /** Joined slug, e.g. "raxis-concepts/01-claims-and-gates". */
  slugPath: string;
  /** Path on disk relative to the docs root, e.g. "raxis-concepts/01-claims-and-gates.md". */
  relativePath: string;
  /** Best-effort human-readable title. */
  title: string;
  /** Doc category for sidebar grouping. */
  category: DocCategory;
  /** Optional sub-section within a category (e.g. "v1", "v2", "scenarios"). */
  subgroup?: string;
  /** Short snippet for the docs index. */
  snippet: string;
  /** Heading skeleton (H2/H3) for in-page TOC and search. */
  headings: Array<{ depth: 2 | 3; text: string; id: string }>;
  /** Display order within its category (for sorted sidebars). */
  order: number;
}

export interface DocFull extends DocMeta {
  /** Rendered HTML from the markdown body. */
  html: string;
  /** Plain-text version of the body, used for search snippets. */
  plain: string;
}

const DOCS_DIR = path.join(process.cwd(), "vendor", "raxis-docs");

// Paths under the source repo that exist as markdown but are not real
// product documentation — generated artifacts, release-pipeline scaffolding,
// auto-generated migration READMEs, scenario templates, GitHub config, etc.
// We hide them from the docs index but still mirror them under vendor/ in
// case anyone deep-links a documented commit.
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
  /^_/, // e.g. _template.md
  /^changelog\.md$/i,
  /^license\.md$/i,
  /^contributing\.md$/i,
];

function isExcluded(rel: string): boolean {
  const segs = rel.split(path.sep);
  const norm = segs.join("/").toLowerCase();
  for (const p of EXCLUDE_PREFIXES) {
    if (norm === p.replace(/\/$/, "") + ".md") return true;
    if (norm.startsWith(p.toLowerCase())) return true;
  }
  // Treat any path segment starting with `_` as private (mirrors the Jekyll
  // / 11ty / docusaurus convention so `_template/`, `_drafts/`, etc. are all
  // hidden without per-name configuration).
  for (const seg of segs) {
    if (seg.startsWith("_")) return true;
  }
  const base = path.basename(rel);
  for (const re of EXCLUDE_BASENAME_PATTERNS) if (re.test(base)) return true;
  return false;
}

function exists(p: string) {
  try {
    fs.accessSync(p);
    return true;
  } catch {
    return false;
  }
}

function safeReadDirRecursive(root: string): string[] {
  const out: string[] = [];
  if (!exists(root)) return out;
  const stack: string[] = [root];
  while (stack.length) {
    const dir = stack.pop()!;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const e of entries) {
      const full = path.join(dir, e.name);
      // Skip noisy dirs that occasionally appear in the source repo.
      if (e.isDirectory()) {
        if (
          e.name === "node_modules" ||
          e.name === ".git" ||
          e.name === "target" ||
          e.name === "dist" ||
          e.name === "build" ||
          e.name === ".next"
        ) {
          continue;
        }
        stack.push(full);
      } else if (e.isFile() && e.name.toLowerCase().endsWith(".md")) {
        out.push(full);
      }
    }
  }
  return out;
}

/**
 * Convert a filesystem-relative markdown path into the URL slug used by
 * `/docs/[...slug]`. `*\/README.md` collapses to its parent directory so the
 * scenario URLs read naturally.
 */
function pathToSlug(rel: string): string[] {
  // Normalize slashes for cross-platform safety.
  const norm = rel.split(path.sep).join("/");
  let withoutExt = norm.replace(/\.md$/i, "");
  // Collapse trailing /README into the directory name.
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

/**
 * Best-effort title extraction. Prefers frontmatter `title`, then first H1,
 * then a humanized form of the filename.
 */
function extractTitle(filename: string, frontmatter: Record<string, any>, body: string): string {
  if (frontmatter.title && typeof frontmatter.title === "string") return frontmatter.title;
  const h1 = /^#\s+(.+)$/m.exec(body);
  if (h1) return h1[1].replace(/[`*_]/g, "").trim();
  const base = filename.replace(/\.md$/i, "").replace(/^README$/i, "Overview");
  return base
    .replace(/[-_]+/g, " ")
    .replace(/\b\w/g, (m) => m.toUpperCase());
}

function snippet(text: string, limit = 220): string {
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
    if (/^```/.test(line)) {
      inFence = !inFence;
      continue;
    }
    if (inFence) continue;
    const m = /^(#{2,3})\s+(.+?)\s*$/.exec(line);
    if (!m) continue;
    const depth = m[1].length === 2 ? 2 : 3;
    const text = m[2].replace(/[`*_]/g, "").trim();
    const id = slugifyHeading(text);
    out.push({ depth: depth as 2 | 3, text, id });
  }
  return out;
}

function slugifyHeading(text: string): string {
  // Mirrors github-slugger's behavior closely enough for in-page anchors.
  return text
    .toLowerCase()
    .replace(/[^\p{L}\p{N}\s-]+/gu, "")
    .trim()
    .replace(/\s+/g, "-");
}

/**
 * Order keys per category for deterministic sidebar rendering. Numbered
 * concept files sort by their leading number; the rest sort alphabetically.
 */
function orderFor(category: DocCategory, slugPath: string, title: string): number {
  if (category === "Concepts") {
    const m = /\/(\d+)-/.exec(slugPath);
    if (m) return parseInt(m[1], 10);
  }
  if (category === "Scenarios") {
    const m = /\/(\d+)-/.exec(slugPath);
    if (m) return parseInt(m[1], 10);
  }
  if (category === "Overview") {
    // Promote a few canonical files to the top.
    if (/\/?readme$/i.test(slugPath)) return 0;
    if (/positioning$/i.test(slugPath)) return 1;
  }
  return 1000 + (title.charCodeAt(0) || 0);
}

let _cache: DocMeta[] | null = null;

export function getAllDocs(): DocMeta[] {
  if (_cache) return _cache;
  if (!exists(DOCS_DIR)) {
    _cache = [];
    return _cache;
  }
  const files = safeReadDirRecursive(DOCS_DIR);
  const docs: DocMeta[] = [];
  for (const abs of files) {
    const rel = path.relative(DOCS_DIR, abs);
    if (isExcluded(rel)) continue;
    let raw: string;
    try {
      raw = fs.readFileSync(abs, "utf8");
    } catch {
      continue;
    }
    const parsed = matter(raw);
    const body = parsed.content;
    const slug = pathToSlug(rel);
    const slugPath = slug.join("/");
    const filename = path.basename(rel);
    const title = extractTitle(filename, parsed.data ?? {}, body);
    const { category, subgroup } = categorize(rel);
    const headings = extractHeadings(body);
    const order = orderFor(category, slugPath, title);
    docs.push({
      slug,
      slugPath,
      relativePath: rel,
      title,
      category,
      subgroup,
      snippet: snippet(body),
      headings,
      order,
    });
  }
  docs.sort((a, b) => {
    if (a.category !== b.category) return a.category.localeCompare(b.category);
    if ((a.subgroup ?? "") !== (b.subgroup ?? ""))
      return (a.subgroup ?? "").localeCompare(b.subgroup ?? "");
    if (a.order !== b.order) return a.order - b.order;
    return a.title.localeCompare(b.title);
  });
  _cache = docs;
  return docs;
}

export interface TomlFile {
  filename: string;
  content: string;
}

/** Returns TOML config files (plan, policy, credential) for a scenario doc. */
export function getScenarioTomlFiles(meta: DocMeta): TomlFile[] {
  if (meta.category !== "Scenarios") return [];
  const dir = path.join(DOCS_DIR, path.dirname(meta.relativePath));
  if (!exists(dir)) return [];
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return [];
  }
  const files: TomlFile[] = [];
  for (const e of entries) {
    if (!e.isFile()) continue;
    if (path.extname(e.name).toLowerCase() !== ".toml") continue;
    try {
      const content = fs.readFileSync(path.join(dir, e.name), "utf8");
      files.push({ filename: e.name, content });
    } catch {
      /* skip unreadable */
    }
  }
  // Canonical order: plan → policy → credential → everything else
  const ORDER = ["plan.toml", "policy.toml", "credential.toml"];
  files.sort((a, b) => {
    const ai = ORDER.indexOf(a.filename);
    const bi = ORDER.indexOf(b.filename);
    if (ai !== -1 && bi !== -1) return ai - bi;
    if (ai !== -1) return -1;
    if (bi !== -1) return 1;
    return a.filename.localeCompare(b.filename);
  });
  return files;
}

export function getDocBySlug(slug: string[]): { meta: DocMeta; raw: string } | null {
  const slugPath = slug.join("/").toLowerCase();
  const meta = getAllDocs().find((d) => d.slugPath === slugPath);
  if (!meta) return null;
  const abs = path.join(DOCS_DIR, meta.relativePath);
  try {
    return { meta, raw: fs.readFileSync(abs, "utf8") };
  } catch {
    return null;
  }
}

export interface DocsByCategory {
  category: DocCategory;
  groups: Array<{ subgroup: string | undefined; docs: DocMeta[] }>;
}

const CATEGORY_ORDER: DocCategory[] = [
  "Overview",
  "Concepts",
  "Specs",
  "Guides",
  "Scenarios",
  "Perspectives",
];

export function getDocsByCategory(): DocsByCategory[] {
  const all = getAllDocs();
  const grouped: Record<DocCategory, Map<string | undefined, DocMeta[]>> = {
    Overview: new Map(),
    Concepts: new Map(),
    Specs: new Map(),
    Guides: new Map(),
    Scenarios: new Map(),
    Perspectives: new Map(),
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
    const groups = Array.from(m.entries()).map(([subgroup, docs]) => ({
      subgroup,
      docs,
    }));
    // Stable subgroup order — explicit for Specs.
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
