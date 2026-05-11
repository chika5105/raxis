import type { Metadata } from "next";
import Link from "next/link";
import { getDocsByCategory, categoryDescription } from "@/lib/docs";
import { DocsSidebar } from "@/components/DocsSidebar";

export const metadata: Metadata = {
  title: "Documentation",
  description:
    "Everything needed to evaluate, implement, operate, or audit Raxis: the paradigm spec, the reference implementation specs, every concept guide, fifty end-to-end scenarios.",
};

export default function DocsIndexPage() {
  const sections = getDocsByCategory();
  const totalCount = sections.reduce(
    (n, s) => n + s.groups.reduce((m, g) => m + g.docs.length, 0),
    0,
  );

  return (
    <div className="mx-auto max-w-7xl px-4 sm:px-6 py-12 lg:py-16 grid gap-12 lg:grid-cols-[240px_minmax(0,1fr)]">
      <aside className="hidden lg:block">
        <div className="sticky top-24 max-h-[calc(100dvh-7rem)] overflow-y-auto pr-3">
          <DocsSidebar />
        </div>
      </aside>

      <div className="min-w-0">
        <header className="mb-14">
          <p className="eyebrow">Documentation</p>
          <h1 className="h-section mt-4">
            Everything needed to evaluate, implement, or audit Raxis
          </h1>
          <p className="subtitle mt-4 max-w-2xl">
            Pulled from the source repository at build time.
            {totalCount > 0 && <> {totalCount} documents indexed.</>}
          </p>
          <div className="mt-7">
            <Link
              href="/docs/search"
              className="inline-flex items-center gap-2 text-base text-[var(--fg)] hover:text-accent transition"
            >
              <svg
                width="16"
                height="16"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="2"
              >
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
          <div className="space-y-16">
            {sections.map((section) => (
              <section key={section.category}>
                <div className="border-b border-[var(--rule)] pb-4 mb-6">
                  <h2 className="h-sub">{section.category}</h2>
                  <p className="mt-2 text-[0.95rem] text-[var(--muted)] max-w-3xl leading-relaxed">
                    {categoryDescription(section.category)}
                  </p>
                </div>
                {section.groups.map((group) => (
                  <div
                    key={(group.subgroup ?? "default") + section.category}
                    className="mb-8"
                  >
                    {group.subgroup && (
                      <h3 className="mb-3 text-xs font-semibold uppercase tracking-wider text-[var(--soft)]">
                        {group.subgroup}
                      </h3>
                    )}
                    <ul className="grid gap-x-10 gap-y-3 sm:grid-cols-2">
                      {group.docs.map((doc) => (
                        <li
                          key={doc.slugPath}
                          className="border-b border-[var(--rule)] pb-2.5"
                        >
                          <Link
                            href={`/docs/${doc.slugPath}`}
                            className="block group"
                          >
                            <div className="text-[var(--fg)] group-hover:text-accent transition truncate">
                              {doc.title}
                            </div>
                            <div className="text-xs font-mono text-[var(--soft)] truncate mt-0.5">
                              /{doc.slugPath}
                            </div>
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
    <div className="border border-dashed border-[var(--rule)] rounded-md p-10 text-center">
      <h2 className="h-sub">No documentation indexed yet</h2>
      <p className="mt-4 text-[var(--muted)] max-w-prose mx-auto leading-relaxed">
        Set{" "}
        <code className="px-1 rounded bg-[var(--code-bg)] font-mono text-[0.88em]">
          RAXIS_REPO_PATH
        </code>{" "}
        to a local raxis checkout (or{" "}
        <code className="px-1 rounded bg-[var(--code-bg)] font-mono text-[0.88em]">
          RAXIS_REPO_URL
        </code>{" "}
        to a public git URL) and rebuild.
      </p>
    </div>
  );
}
