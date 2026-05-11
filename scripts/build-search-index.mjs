#!/usr/bin/env node
// Build a serialized MiniSearch index over every doc in vendor/raxis-docs/
// and write it to public/search-index.json. The client loads this once on
// the search page and runs all queries locally — no API, no telemetry.

import fs from "node:fs";
import path from "node:path";
import url from "node:url";
import matter from "gray-matter";
import MiniSearch from "minisearch";

const __filename = url.fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT = path.resolve(__dirname, "..");
const DOCS_DIR = path.join(ROOT, "vendor", "raxis-docs");
const PUBLIC_DIR = path.join(ROOT, "public");
const OUT = path.join(PUBLIC_DIR, "search-index.json");

function log(msg) {
  process.stdout.write(`[search] ${msg}\n`);
}

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
const EXCLUDE_BASENAME_PATTERNS = [/^_/, /^changelog\.md$/i, /^license\.md$/i, /^contributing\.md$/i];

function isExcluded(rel) {
  const segs = rel.split(path.sep);
  const norm = segs.join("/").toLowerCase();
  for (const p of EXCLUDE_PREFIXES) {
    if (norm === p.replace(/\/$/, "") + ".md") return true;
    if (norm.startsWith(p.toLowerCase())) return true;
  }
  for (const seg of segs) {
    if (seg.startsWith("_")) return true;
  }
  const base = path.basename(rel);
  for (const re of EXCLUDE_BASENAME_PATTERNS) if (re.test(base)) return true;
  return false;
}

function listMarkdown(root) {
  const out = [];
  if (!fs.existsSync(root)) return out;
  const stack = [root];
  while (stack.length) {
    const dir = stack.pop();
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const e of entries) {
      const abs = path.join(dir, e.name);
      if (e.isDirectory()) {
        stack.push(abs);
      } else if (e.isFile() && /\.md$/i.test(e.name)) {
        out.push(abs);
      }
    }
  }
  return out;
}

function pathToSlug(rel) {
  const norm = rel.split(path.sep).join("/");
  let withoutExt = norm.replace(/\.md$/i, "");
  withoutExt = withoutExt.replace(/\/README$/i, "");
  if (withoutExt === "README") withoutExt = "readme";
  return withoutExt.toLowerCase();
}

function categorize(rel) {
  const norm = rel.split(path.sep).join("/").toLowerCase();
  if (norm.startsWith("raxis-concepts/")) return "Concepts";
  if (norm.startsWith("specs/")) return "Specs";
  if (norm.startsWith("guides/scenarios/")) return "Scenarios";
  if (norm.startsWith("guides/")) return "Guides";
  if (norm.startsWith("perspectives/")) return "Perspectives";
  return "Overview";
}

function extractTitle(filename, fm, body) {
  if (fm.title && typeof fm.title === "string") return fm.title;
  const h1 = /^#\s+(.+)$/m.exec(body);
  if (h1) return h1[1].replace(/[`*_]/g, "").trim();
  const base = filename.replace(/\.md$/i, "").replace(/^README$/i, "Overview");
  return base.replace(/[-_]+/g, " ").replace(/\b\w/g, (m) => m.toUpperCase());
}

function extractHeadings(body) {
  const lines = body.split("\n");
  let inFence = false;
  const out = [];
  for (const line of lines) {
    if (/^```/.test(line)) {
      inFence = !inFence;
      continue;
    }
    if (inFence) continue;
    const m = /^(#{2,3})\s+(.+?)\s*$/.exec(line);
    if (m) out.push(m[2].replace(/[`*_]/g, "").trim());
  }
  return out;
}

function toPlain(body) {
  return body
    .replace(/```[\s\S]*?```/g, " ")
    .replace(/`[^`\n]+`/g, " ")
    .replace(/^#+\s+/gm, "")
    .replace(/\[(.*?)\]\((.*?)\)/g, "$1")
    .replace(/[*_~>|#-]+/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function snippet(text, limit = 280) {
  if (text.length <= limit) return text;
  return text.slice(0, limit).replace(/\s+\S*$/, "") + "…";
}

function buildIndex() {
  if (!fs.existsSync(DOCS_DIR)) {
    log(`no docs dir at ${DOCS_DIR}; writing empty index`);
    fs.mkdirSync(PUBLIC_DIR, { recursive: true });
    fs.writeFileSync(OUT, JSON.stringify({ index: null, docs: [] }), "utf8");
    return;
  }
  const files = listMarkdown(DOCS_DIR);
  const docs = [];
  for (const abs of files) {
    const rel = path.relative(DOCS_DIR, abs);
    if (isExcluded(rel)) continue;
    let raw;
    try {
      raw = fs.readFileSync(abs, "utf8");
    } catch {
      continue;
    }
    const parsed = matter(raw);
    const body = parsed.content;
    const title = extractTitle(path.basename(rel), parsed.data ?? {}, body);
    const headings = extractHeadings(body);
    const plain = toPlain(body);
    docs.push({
      id: pathToSlug(rel),
      slug: pathToSlug(rel),
      title,
      category: categorize(rel),
      headings: headings.join(" · "),
      snippet: snippet(plain),
      // Cap the indexed body to keep the JSON reasonable on disk.
      body: plain.slice(0, 6000),
    });
  }

  const ms = new MiniSearch({
    fields: ["title", "headings", "body", "slug"],
    storeFields: ["title", "category", "snippet", "slug", "headings"],
    searchOptions: {
      boost: { title: 4, headings: 2, slug: 1.5 },
      prefix: true,
      fuzzy: 0.15,
    },
  });
  ms.addAll(docs);

  fs.mkdirSync(PUBLIC_DIR, { recursive: true });
  fs.writeFileSync(
    OUT,
    JSON.stringify({
      index: ms.toJSON(),
      meta: docs.map((d) => ({
        id: d.id,
        slug: d.slug,
        title: d.title,
        category: d.category,
        snippet: d.snippet,
      })),
      builtAt: new Date().toISOString(),
      count: docs.length,
    }),
    "utf8",
  );
  log(`indexed ${docs.length} docs → ${path.relative(ROOT, OUT)}`);
}

try {
  buildIndex();
} catch (err) {
  console.error("[search] failed:", err);
  process.exit(1);
}
