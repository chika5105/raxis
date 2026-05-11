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

export interface RenderResult {
  html: string;
  plain: string;
}

export async function renderMarkdown(raw: string): Promise<RenderResult> {
  const { content } = matter(raw);
  // The page provides its own H1 from the doc metadata. Strip the leading H1
  // from the body so the rendered article doesn't show the title twice.
  const body = stripLeadingH1(content);
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
  // Skip blank lines and front-matter-style noise, then drop the first H1
  // line if present. We do not strip H1s mid-document — only the first one,
  // and only if it's the first non-blank line.
  const lines = markdown.split("\n");
  let i = 0;
  while (i < lines.length && lines[i].trim() === "") i++;
  if (i < lines.length && /^#\s+/.test(lines[i])) {
    lines.splice(i, 1);
    // Also collapse the blank line directly after.
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
