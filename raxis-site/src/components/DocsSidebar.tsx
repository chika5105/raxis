import Link from "next/link";
import { getDocsByCategory } from "@/lib/docs";
import clsx from "clsx";
import { DocsSidebarSection } from "./DocsSidebarSection";

interface Props {
  /** slugPath of the currently active doc (e.g. "raxis-concepts/01-claims-and-gates"). */
  active?: string;
}

export async function DocsSidebar({ active }: Props) {
  const sections = await getDocsByCategory();

  return (
    <nav aria-label="Documentation" className="text-sm">
      <div className="mb-8">
        <Link
          href="/docs"
          className={clsx(
            "block py-1.5 text-sm transition",
            !active
              ? "text-accent font-medium"
              : "text-[var(--muted)] hover:text-[var(--fg)]",
          )}
        >
          Index
        </Link>
        <Link
          href="/docs/search"
          className="block py-1.5 text-sm text-[var(--muted)] hover:text-[var(--fg)] transition"
        >
          Search →
        </Link>
      </div>

      {sections.map((section) => {
        // Auto-expand the section that contains the active doc.
        const containsActive = active
          ? section.groups.some((g) => g.docs.some((d) => d.slugPath === active))
          : false;

        return (
          <DocsSidebarSection
            key={section.category}
            category={section.category}
            groups={section.groups}
            active={active}
            defaultOpen={
              containsActive ||
              section.category === "Overview" ||
              section.category === "Guides"
            }
          />
        );
      })}
    </nav>
  );
}
