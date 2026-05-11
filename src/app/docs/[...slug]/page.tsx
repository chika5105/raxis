import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { getAllDocs, getDocBySlug } from "@/lib/docs";
import { renderMarkdown } from "@/lib/markdown";
import { DocsSidebar } from "@/components/DocsSidebar";

interface Params {
  params: Promise<{ slug: string[] }>;
}

export async function generateStaticParams() {
  return getAllDocs().map((doc) => ({ slug: doc.slug }));
}

export async function generateMetadata({ params }: Params): Promise<Metadata> {
  const { slug } = await params;
  const found = getDocBySlug(slug);
  if (!found) return { title: "Not found" };
  return {
    title: found.meta.title,
    description: found.meta.snippet,
  };
}

export default async function DocPage({ params }: Params) {
  const { slug } = await params;
  const found = getDocBySlug(slug);
  if (!found) notFound();
  const { html } = await renderMarkdown(found.raw);
  const { meta } = found;
  const all = getAllDocs();
  const idx = all.findIndex((d) => d.slugPath === meta.slugPath);
  const prev = idx > 0 ? all[idx - 1] : null;
  const next = idx >= 0 && idx < all.length - 1 ? all[idx + 1] : null;

  return (
    <div className="mx-auto max-w-7xl px-4 sm:px-6 py-10 lg:py-14 grid gap-10 lg:grid-cols-[240px_minmax(0,1fr)_220px]">
      <aside className="hidden lg:block">
        <div className="sticky top-24 max-h-[calc(100dvh-7rem)] overflow-y-auto pr-3">
          <DocsSidebar active={meta.slugPath} />
        </div>
      </aside>

      <article className="min-w-0">
        <Breadcrumb meta={meta} />
        <h1 className="mt-3 text-3xl sm:text-4xl font-semibold tracking-[-0.02em] leading-tight">
          {meta.title}
        </h1>
        <div className="mt-3 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-[var(--muted)] font-mono">
          <span className="text-accent">{meta.category}</span>
          {meta.subgroup && <><span aria-hidden>·</span><span>{meta.subgroup}</span></>}
          <span aria-hidden>·</span>
          <span title="Source path in the raxis repo">{meta.relativePath}</span>
        </div>

        <div className="mt-8 doc-prose" dangerouslySetInnerHTML={{ __html: html }} />

        <PrevNext prev={prev ?? undefined} next={next ?? undefined} />
      </article>

      <aside className="hidden xl:block">
        <div className="sticky top-24 max-h-[calc(100dvh-7rem)] overflow-y-auto">
          <OnThisPage headings={meta.headings} />
        </div>
      </aside>
    </div>
  );
}

function Breadcrumb({ meta }: { meta: import("@/lib/docs").DocMeta }) {
  return (
    <nav aria-label="Breadcrumb" className="text-xs text-[var(--muted)]">
      <ol className="flex flex-wrap items-center gap-1">
        <li><Link href="/docs" className="hover:text-[var(--fg)]">Docs</Link></li>
        <li aria-hidden>/</li>
        <li><span className="text-accent">{meta.category}</span></li>
        {meta.subgroup && (
          <>
            <li aria-hidden>/</li>
            <li>{meta.subgroup}</li>
          </>
        )}
      </ol>
    </nav>
  );
}

function OnThisPage({ headings }: { headings: Array<{ depth: 2 | 3; text: string; id: string }> }) {
  if (!headings.length) return null;
  return (
    <nav aria-label="On this page" className="text-sm">
      <h4 className="text-[10px] font-mono uppercase tracking-[0.18em] text-[var(--muted)] mb-2">
        On this page
      </h4>
      <ul className="space-y-1.5 border-l border-[var(--rule)]">
        {headings.map((h, i) => (
          <li
            key={`${i}-${h.id}`}
            style={{ paddingLeft: h.depth === 2 ? "0.75rem" : "1.5rem" }}
          >
            <a
              href={`#${h.id}`}
              className="block text-[13px] leading-tight text-[var(--muted)] hover:text-[var(--fg)] truncate"
              title={h.text}
            >
              {h.text}
            </a>
          </li>
        ))}
      </ul>
    </nav>
  );
}

function PrevNext({
  prev,
  next,
}: {
  prev?: import("@/lib/docs").DocMeta;
  next?: import("@/lib/docs").DocMeta;
}) {
  if (!prev && !next) return null;
  return (
    <div className="mt-12 grid gap-3 sm:grid-cols-2 border-t border-[var(--rule)] pt-6">
      {prev ? (
        <Link
          href={`/docs/${prev.slugPath}`}
          className="rounded-lg border border-[var(--card-rule)] bg-[var(--card)] p-4 hover:border-accent transition"
        >
          <div className="text-[10px] font-mono uppercase tracking-wider text-[var(--muted)]">← Previous</div>
          <div className="mt-1 font-medium tracking-tight truncate">{prev.title}</div>
        </Link>
      ) : (
        <div />
      )}
      {next ? (
        <Link
          href={`/docs/${next.slugPath}`}
          className="rounded-lg border border-[var(--card-rule)] bg-[var(--card)] p-4 hover:border-accent transition text-right"
        >
          <div className="text-[10px] font-mono uppercase tracking-wider text-[var(--muted)]">Next →</div>
          <div className="mt-1 font-medium tracking-tight truncate">{next.title}</div>
        </Link>
      ) : (
        <div />
      )}
    </div>
  );
}
