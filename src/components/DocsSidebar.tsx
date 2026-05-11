import Link from "next/link";
import { getDocsByCategory } from "@/lib/docs";
import clsx from "clsx";

interface Props {
  /** slugPath of the currently active doc (e.g. "raxis-concepts/01-claims-and-gates"). */
  active?: string;
}

export function DocsSidebar({ active }: Props) {
  const sections = getDocsByCategory();
  return (
    <nav aria-label="Documentation" className="space-y-7 text-sm">
      <div>
        <Link
          href="/docs"
          className={clsx(
            "block rounded-md px-2 py-1.5 text-sm font-medium",
            !active
              ? "bg-accent-soft text-accent"
              : "text-[var(--muted)] hover:text-[var(--fg)] hover:bg-[var(--card)]",
          )}
        >
          Index
        </Link>
        <Link
          href="/docs/search"
          className="mt-1 block rounded-md px-2 py-1.5 text-sm text-[var(--muted)] hover:text-[var(--fg)] hover:bg-[var(--card)]"
        >
          Search docs →
        </Link>
      </div>
      {sections.map((section) => (
        <div key={section.category}>
          <h3 className="px-2 mb-2 text-[10px] font-mono uppercase tracking-[0.18em] text-[var(--muted)]">
            {section.category}
          </h3>
          <div className="space-y-4">
            {section.groups.map((group) => (
              <div key={(group.subgroup ?? "default") + section.category}>
                {group.subgroup && (
                  <div className="px-2 mb-1 text-xs font-medium text-[var(--fg)]">{group.subgroup}</div>
                )}
                <ul className="space-y-0.5">
                  {group.docs.map((doc) => {
                    const isActive = active === doc.slugPath;
                    return (
                      <li key={doc.slugPath}>
                        <Link
                          href={`/docs/${doc.slugPath}`}
                          className={clsx(
                            "block truncate rounded-md px-2 py-1 text-[13px] leading-tight",
                            isActive
                              ? "bg-accent-soft text-accent font-medium"
                              : "text-[var(--muted)] hover:text-[var(--fg)] hover:bg-[var(--card)]",
                          )}
                          title={doc.title}
                        >
                          {doc.title}
                        </Link>
                      </li>
                    );
                  })}
                </ul>
              </div>
            ))}
          </div>
        </div>
      ))}
    </nav>
  );
}
