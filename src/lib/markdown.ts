// Markdown → HTML pipeline.
//
// All transformation happens at build time inside React Server Components.
// The output HTML is injected into a `.doc-prose` container whose CSS lives
// in `globals.css`. We rely on `rehype-pretty-code` (Shiki) for syntax
// highlighting — Shiki ships server-side only, so the client bundle stays
// free of any highlighter weight.

import { unified } from "unified";
import remarkParse from "remark-parse";
import remarkGfm from "remark-gfm";
import remarkRehype from "remark-rehype";
import rehypeSlug from "rehype-slug";
import rehypeAutolinkHeadings from "rehype-autolink-headings";
import rehypePrettyCode from "rehype-pretty-code";
import rehypeStringify from "rehype-stringify";
import matter from "gray-matter";
import type { Plugin } from "unified";
import type { Root, Element } from "hast";
import { visit } from "unist-util-visit";

export interface RenderResult {
  html: string;
  plain: string;
}

// ─── Relative .md link rewriter ──────────────────────────────────────────────
//
// Markdown files cross-link each other using relative paths, e.g.:
//   [foo](../specs/design-decisions.md)
//   [bar](raxis-defense.md)
//   [specs](../specs/)
//
// In the browser those hrefs are invalid. This rehype plugin resolves them
// against the current doc's directory and rewrites them to /docs/… routes.

function mdPathToDocSlug(resolvedRel: string): string {
  // Strip .md / trailing /index.md / trailing README.md
  let s = resolvedRel
    .replace(/\.md$/i, "")
    .replace(/\/README$/i, "")
    .replace(/\/index$/i, "");
  if (s === "README" || s === "index") s = "";
  // Lowercase, clean up leading slashes
  return s.toLowerCase().replace(/^\/+/, "");
}

function resolveRelativeHref(href: string, docDir: string): string | null {
  // Skip anchors, absolute URLs, and already-absolute paths
  if (href.startsWith("#") || href.startsWith("http") || href.startsWith("/")) {
    return null;
  }

  // Combine docDir + href and normalise ../ segments
  const parts = (docDir + "/" + href).split("/").filter(Boolean);
  const resolved: string[] = [];
  for (const p of parts) {
    if (p === "..") resolved.pop();
    else if (p !== ".") resolved.push(p);
  }
  return resolved.join("/");
}

function rehypeMdLinks(docDir: string): Plugin<[], Root> {
  return () => (tree: Root) => {
    visit(tree, "element", (node: Element) => {
      if (node.tagName !== "a") return;
      const href = node.properties?.href;
      if (typeof href !== "string") return;

      // Strip any fragment before resolving
      const [pathPart, fragment] = href.split("#");

      // Directory-only links like ../specs/ → /docs/specs
      const isDirLink = pathPart.endsWith("/") && !pathPart.endsWith(".md");
      const isMdLink = pathPart.endsWith(".md") || pathPart.endsWith(".mdx");

      if (!isMdLink && !isDirLink) return;

      const resolved = resolveRelativeHref(pathPart, docDir);
      if (!resolved) return;

      const slugPath = isMdLink
        ? mdPathToDocSlug(resolved)
        : resolved.toLowerCase().replace(/^\/+/, "").replace(/\/+$/, "");

      if (!slugPath) return;

      const newHref = `/docs/${slugPath}${fragment ? "#" + fragment : ""}`;
      node.properties = { ...node.properties, href: newHref };
    });
  };
}

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * @param raw      The raw markdown string (including any front-matter).
 * @param docPath  The doc's relative path inside the docs root, e.g.
 *                 "perspectives/README.md". Used to resolve sibling links.
 */
export async function renderMarkdown(
  raw: string,
  docPath = ""
): Promise<RenderResult> {
  const { content } = matter(raw);
  // The page provides its own H1 from the doc metadata. Strip the leading H1
  // from the body so the rendered article doesn't show the title twice.
  const body = stripLeadingH1(content);

  // Directory of the current doc (e.g. "perspectives")
  const docDir = docPath.split("/").slice(0, -1).join("/");

  const file = await unified()
    .use(remarkParse)
    .use(remarkGfm)
    .use(remarkRehype, { allowDangerousHtml: false })
    .use(rehypeSlug)
    .use(rehypeAutolinkHeadings, {
      behavior: "append",
      properties: { className: ["heading-anchor"], "aria-label": "Link to section" },
      content: { type: "text", value: "#" },
    })
    .use(rehypeMdLinks(docDir) as Plugin<[], Root>)
    .use(rehypePrettyCode, {
      theme: { light: "github-light", dark: "github-dark" },
      keepBackground: false,
      defaultLang: "text",
    })
    .use(rehypeStringify)
    .process(body);

  return {
    html: String(file),
    plain: toPlain(body),
  };
}

function stripLeadingH1(markdown: string): string {
  const lines = markdown.split("\n");
  let i = 0;
  while (i < lines.length && lines[i].trim() === "") i++;
  if (i < lines.length && /^#\s+/.test(lines[i])) {
    lines.splice(i, 1);
    if (i < lines.length && lines[i].trim() === "") lines.splice(i, 1);
    return lines.join("\n");
  }
  return markdown;
}

function toPlain(markdown: string): string {
  return markdown
    .replace(/```[\s\S]*?```/g, " ")
    .replace(/`[^`\n]+`/g, " ")
    .replace(/^#+\s+/gm, "")
    .replace(/\[(.*?)\]\((.*?)\)/g, "$1")
    .replace(/[*_~>|]/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}
