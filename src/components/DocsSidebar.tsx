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
            "block py-1 text-sm transition",
            !active
              ? "text-accent font-medium"
              : "text-[var(--muted)] hover:text-[var(--fg)]",
          )}
        >
          Index
        </Link>
        <Link
          href="/docs/search"
          className="block py-1 text-sm text-[var(--muted)] hover:text-[var(--fg)] transition"
        >
          Search →
        </Link>
      </div>
      {sections.map((section) => (
        <div key={section.category}>
          <h3 className="mb-2 text-xs font-semibold uppercase tracking-wider text-[var(--muted)]">
            {section.category}
          </h3>
          <div className="space-y-4">
            {section.groups.map((group) => (
              <div key={(group.subgroup ?? "default") + section.category}>
                {group.subgroup && (
                  <div className="mb-1 text-[13px] font-medium text-[var(--muted)]">{group.subgroup}</div>
                )}
                <ul className="space-y-0.5 border-l border-[var(--rule)]">
                  {group.docs.map((doc) => {
                    const isActive = active === doc.slugPath;
                    return (
                      <li key={doc.slugPath}>
                        <Link
                          href={`/docs/${doc.slugPath}`}
                          className={clsx(
                            "block truncate -ml-px border-l py-1 pl-3 text-[13px] leading-snug transition",
                            isActive
                              ? "border-accent text-accent font-medium"
                              : "border-transparent text-[var(--muted)] hover:text-[var(--fg)] hover:border-[var(--rule)]",
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
