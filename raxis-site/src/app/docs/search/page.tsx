import type { Metadata } from "next";
import { DocsSidebar } from "@/components/DocsSidebar";
import { SearchClient } from "@/components/SearchClient";

export const metadata: Metadata = {
  title: "Search documentation",
  description:
    "Full-text search across every Raxis spec, concept guide, scenario, and perspective. Runs in your browser.",
};

export default function SearchPage() {
  return (
    <div className="mx-auto max-w-7xl px-4 sm:px-6 py-12 lg:py-16 grid gap-12 lg:grid-cols-[240px_minmax(0,1fr)]">
      <aside className="hidden lg:block">
        <div className="sticky top-24 max-h-[calc(100dvh-7rem)] overflow-y-auto pr-3">
          <DocsSidebar />
        </div>
      </aside>
      <div className="min-w-0">
        <header className="mb-10">
          <p className="eyebrow">Search</p>
          <h1 className="h-section mt-4">Search the documentation</h1>
          <p className="subtitle mt-4 max-w-2xl">
            Full-text search across every spec, concept guide, scenario, and
            perspective. The index is downloaded once and cached; queries run
            in your browser.
          </p>
        </header>
        <SearchClient />
      </div>
    </div>
  );
}
