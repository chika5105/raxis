import type { Metadata } from "next";
import { DocsSidebar } from "@/components/DocsSidebar";
import { ResizableSidebar } from "@/components/ResizableSidebar";
import { SearchClient } from "@/components/SearchClient";

export const metadata: Metadata = {
  title: "Search documentation",
  description:
    "Full-text search across every Raxis spec, concept guide, scenario, and perspective. Runs in your browser.",
};

export default function SearchPage() {
  return (
    <div className="w-full px-6 xl:px-12 py-10 lg:py-14 flex gap-8 xl:gap-12">
      <aside className="hidden lg:flex shrink-0">
        <ResizableSidebar>
          <div className="sticky top-24 max-h-[calc(100dvh-7rem)] overflow-y-auto pr-3 w-full">
            <DocsSidebar />
          </div>
        </ResizableSidebar>
      </aside>
      <div className="flex-1 min-w-0">
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
