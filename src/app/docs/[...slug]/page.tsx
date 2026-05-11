import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { getAllDocs, getDocBySlug, getScenarioTomlFiles } from "@/lib/docs";
import { renderMarkdown } from "@/lib/markdown";
import { DocsSidebar } from "@/components/DocsSidebar";
import { TomlFileViewer } from "@/components/TomlFileViewer";
import { ResizableSidebar } from "@/components/ResizableSidebar";

interface Params {
  params: Promise<{ slug: string[] }>;
}

export const revalidate = 3600;

export async function generateStaticParams() {
  const docs = await getAllDocs();
  return docs.map((doc) => ({ slug: doc.slug }));
}

export async function generateMetadata({ params }: Params): Promise<Metadata> {
  const { slug } = await params;
  const found = await getDocBySlug(slug);
  if (!found) return { title: "Not found" };
  return {
    title: found.meta.title,
    description: found.meta.snippet,
  };
}

export default async function DocPage({ params }: Params) {
  const { slug } = await params;
  const found = await getDocBySlug(slug);
  if (!found) notFound();
  const { html } = await renderMarkdown(found.raw);
  const { meta } = found;
  const tomlFiles = await getScenarioTomlFiles(meta);
  const all = await getAllDocs();
  const idx = all.findIndex((d) => d.slugPath === meta.slugPath);
  const prev = idx > 0 ? all[idx - 1] : null;
  const next = idx >= 0 && idx < all.length - 1 ? all[idx + 1] : null;

  return (
    <div className="w-full px-6 xl:px-12 py-10 lg:py-14 flex gap-8 xl:gap-12">
      <aside className="hidden lg:flex shrink-0">
        <ResizableSidebar>
          <div className="sticky top-24 max-h-[calc(100dvh-7rem)] overflow-y-auto pr-3 w-full">
            <DocsSidebar active={meta.slugPath} />
          </div>
        </ResizableSidebar>
      </aside>

      <div className="flex-1 min-w-0 flex gap-10">
      <article className="flex-1 min-w-0">
        <Breadcrumb meta={meta} />
        <h1 className="font-display font-semibold tracking-[-0.02em] leading-[1.15] text-[2rem] sm:text-[2.4rem] mt-4">
          {meta.title}
        </h1>
        <div className="mt-3 text-xs text-[var(--soft)] font-mono truncate">
          {meta.relativePath}
        </div>

        <div
          className="mt-10 doc-prose"
          dangerouslySetInnerHTML={{ __html: html }}
        />

        {tomlFiles.length > 0 && (
          <section className="mt-14">
            <div className="flex items-center gap-3 mb-5 pb-3 border-b border-[var(--rule)]">
              <h2 className="text-[1.1rem] font-semibold text-[var(--fg)] tracking-[-0.01em]">
                Scenario files
              </h2>
              <span className="text-xs text-[var(--soft)] tabular-nums">
                {tomlFiles.length} file{tomlFiles.length !== 1 ? "s" : ""}
              </span>
            </div>
            <div className="space-y-2">
              {tomlFiles.map((f, i) => (
                <TomlFileViewer
                  key={f.filename}
                  filename={f.filename}
                  content={f.content}
                  defaultOpen={i === 0}
                />
              ))}
            </div>
          </section>
        )}

        <PrevNext prev={prev ?? undefined} next={next ?? undefined} />
      </article>

      <aside className="hidden xl:block shrink-0 w-[200px]">
        <div className="sticky top-24 max-h-[calc(100dvh-7rem)] overflow-y-auto">
          <OnThisPage headings={meta.headings} />
        </div>
      </aside>
      </div>
    </div>
  );
}

function Breadcrumb({ meta }: { meta: import("@/lib/docs").DocMeta }) {
  return (
    <nav aria-label="Breadcrumb" className="text-xs text-[var(--muted)]">
      <ol className="flex flex-wrap items-center gap-2">
        <li><Link href="/docs" className="hover:text-[var(--fg)]">Docs</Link></li>
        <li aria-hidden>/</li>
        <li className="text-[var(--fg)]">{meta.category}</li>
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
      <h4 className="text-xs font-semibold uppercase tracking-wider text-[var(--muted)] mb-3">
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
    <div className="mt-16 grid gap-6 sm:grid-cols-2 border-t border-[var(--rule)] pt-6">
      {prev ? (
        <Link href={`/docs/${prev.slugPath}`} className="group">
          <div className="text-xs uppercase tracking-wider text-[var(--soft)]">
            ← Previous
          </div>
          <div className="mt-1.5 font-medium text-[var(--fg)] group-hover:text-accent transition truncate">
            {prev.title}
          </div>
        </Link>
      ) : (
        <div />
      )}
      {next ? (
        <Link href={`/docs/${next.slugPath}`} className="group text-right">
          <div className="text-xs uppercase tracking-wider text-[var(--soft)]">
            Next →
          </div>
          <div className="mt-1.5 font-medium text-[var(--fg)] group-hover:text-accent transition truncate">
            {next.title}
          </div>
        </Link>
      ) : (
        <div />
      )}
    </div>
  );
}
