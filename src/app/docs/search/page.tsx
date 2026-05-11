import type { Metadata } from "next";
import { DocsSidebar } from "@/components/DocsSidebar";
import { SearchClient } from "@/components/SearchClient";

export const metadata: Metadata = {
  title: "Search documentation",
  description:
    "Full-text search across every RAXIS spec, concept guide, scenario, and perspective. Runs entirely in your browser — no telemetry, no remote requests.",
};

export default function SearchPage() {
  return (
    <div className="mx-auto max-w-7xl px-4 sm:px-6 py-12 lg:py-16 grid gap-12 lg:grid-cols-[260px_minmax(0,1fr)]">
      <aside className="hidden lg:block">
        <div className="sticky top-24 max-h-[calc(100dvh-7rem)] overflow-y-auto pr-3">
          <DocsSidebar />
        </div>
      </aside>
      <div className="min-w-0">
        <header className="mb-8">
          <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">
            Search
          </p>
          <h1 className="mt-3 text-3xl sm:text-4xl font-semibold tracking-[-0.02em] leading-tight">
            Search the documentation.
          </h1>
          <p className="mt-3 max-w-2xl text-[var(--muted)] leading-relaxed">
            Full-text search across every spec, concept guide, scenario, and perspective. Runs entirely in your browser
            — no API calls, no telemetry. The index is downloaded once on this page and cached.
          </p>
        </header>
        <SearchClient />
      </div>
    </div>
  );
}
