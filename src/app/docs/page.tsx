import type { Metadata } from "next";
import Link from "next/link";
import { getDocsByCategory, categoryDescription } from "@/lib/docs";
import { DocsSidebar } from "@/components/DocsSidebar";

export const metadata: Metadata = {
  title: "Documentation",
  description:
    "Everything you need to evaluate, implement, operate, or audit RAXIS — the paradigm spec, the reference implementation specs, every concept guide, fifty end-to-end scenarios, and the operator certificate ceremony.",
};

export default function DocsIndexPage() {
  const sections = getDocsByCategory();
  const totalCount = sections.reduce(
    (n, s) => n + s.groups.reduce((m, g) => m + g.docs.length, 0),
    0,
  );

  return (
    <div className="mx-auto max-w-7xl px-4 sm:px-6 py-12 lg:py-16 grid gap-12 lg:grid-cols-[260px_minmax(0,1fr)]">
      <aside className="hidden lg:block">
        <div className="sticky top-24 max-h-[calc(100dvh-7rem)] overflow-y-auto pr-3">
          <DocsSidebar />
        </div>
      </aside>

      <div className="min-w-0">
        <header className="mb-12">
          <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">
            Documentation
          </p>
          <h1 className="mt-3 text-3xl sm:text-4xl font-semibold tracking-[-0.02em] leading-tight">
            The RAXIS documentation.
          </h1>
          <p className="mt-4 max-w-2xl text-[var(--muted)] leading-relaxed">
            Everything you need to evaluate, implement, operate, or audit RAXIS — automatically pulled from the source
            repository at build time. {totalCount > 0 && (<><strong className="text-[var(--fg)]">{totalCount}</strong> documents indexed.</>)}
          </p>
          <div className="mt-6 flex flex-wrap items-center gap-2">
            <Link
              href="/docs/search"
              className="inline-flex h-9 items-center gap-2 rounded-md border border-[var(--rule)] px-3 text-sm text-[var(--muted)] hover:text-[var(--fg)] hover:border-[var(--fg)] transition"
            >
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <circle cx="11" cy="11" r="7" />
                <path d="m21 21-4.3-4.3" />
              </svg>
              Search across all documentation
            </Link>
          </div>
        </header>

        {totalCount === 0 ? (
          <EmptyState />
        ) : (
          <div className="space-y-12">
            {sections.map((section) => (
              <section key={section.category}>
                <div className="border-b border-[var(--rule)] pb-3 mb-5">
                  <h2 className="text-xl font-semibold tracking-tight">{section.category}</h2>
                  <p className="mt-1 text-sm text-[var(--muted)] max-w-3xl">
                    {categoryDescription(section.category)}
                  </p>
                </div>
                {section.groups.map((group) => (
                  <div key={(group.subgroup ?? "default") + section.category} className="mb-6">
                    {group.subgroup && (
                      <h3 className="mb-3 text-sm font-medium text-[var(--fg)]">{group.subgroup}</h3>
                    )}
                    <ul className="grid gap-2 sm:grid-cols-2">
                      {group.docs.map((doc) => (
                        <li key={doc.slugPath}>
                          <Link
                            href={`/docs/${doc.slugPath}`}
                            className="block rounded-lg border border-[var(--card-rule)] bg-[var(--card)] p-4 hover:border-accent transition"
                          >
                            <div className="flex items-baseline justify-between gap-3">
                              <h4 className="font-medium tracking-tight truncate">{doc.title}</h4>
                              <span className="font-mono text-[10px] text-[var(--muted)] shrink-0">
                                /{doc.slugPath}
                              </span>
                            </div>
                            {doc.snippet && (
                              <p className="mt-1.5 text-xs text-[var(--muted)] line-clamp-2 leading-relaxed">
                                {doc.snippet}
                              </p>
                            )}
                          </Link>
                        </li>
                      ))}
                    </ul>
                  </div>
                ))}
              </section>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function EmptyState() {
  return (
    <div className="rounded-xl border border-dashed border-[var(--rule)] p-8 text-center">
      <h2 className="text-lg font-semibold tracking-tight">No documentation indexed yet.</h2>
      <p className="mt-3 text-sm text-[var(--muted)] max-w-prose mx-auto">
        Set <code className="px-1 rounded bg-[var(--code-bg)] font-mono text-xs">RAXIS_REPO_PATH</code> to a local raxis
        checkout (or <code className="px-1 rounded bg-[var(--code-bg)] font-mono text-xs">RAXIS_REPO_URL</code> to a
        public git URL) and rebuild. The <code className="px-1 rounded bg-[var(--code-bg)] font-mono text-xs">scripts/sync-docs.mjs</code>{" "}
        step will copy every <code className="px-1 rounded bg-[var(--code-bg)] font-mono text-xs">.md</code> file into{" "}
        <code className="px-1 rounded bg-[var(--code-bg)] font-mono text-xs">vendor/raxis-docs/</code>, and this page
        will populate automatically.
      </p>
    </div>
  );
}
