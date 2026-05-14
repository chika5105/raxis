"use client";

import { useState } from "react";
import Link from "next/link";
import clsx from "clsx";

interface Doc {
  slugPath: string;
  title: string;
}

interface Group {
  subgroup?: string;
  docs: Doc[];
}

interface Props {
  category: string;
  groups: Group[];
  active?: string;
  /** Section starts expanded when it contains the active doc or when forced */
  defaultOpen?: boolean;
}

function ChevronIcon({ open }: { open: boolean }) {
  return (
    <svg
      width="12"
      height="12"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2.5"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      className="shrink-0 transition-transform duration-150"
      style={{ transform: open ? "rotate(0deg)" : "rotate(-90deg)" }}
    >
      <path d="M6 9l6 6 6-6" />
    </svg>
  );
}

export function DocsSidebarSection({ category, groups, active, defaultOpen = false }: Props) {
  const [open, setOpen] = useState(defaultOpen);

  return (
    <div className="mb-8">
      <button
        type="button"
        onClick={() => setOpen(!open)}
        className="w-full flex items-center gap-1.5 mb-3 pt-3 border-t border-[var(--rule)] group"
        aria-expanded={open}
      >
        <span className="flex-1 text-left text-[11px] font-semibold uppercase tracking-widest text-[var(--soft)] group-hover:text-[var(--muted)] transition">
          {category}
        </span>
        <span className="text-[var(--soft)] group-hover:text-[var(--muted)] transition">
          <ChevronIcon open={open} />
        </span>
      </button>

      <div
        className="grid transition-[grid-template-rows] duration-200 ease-in-out"
        style={{ gridTemplateRows: open ? "1fr" : "0fr" }}
      >
        <div className="overflow-hidden">
          <div className="space-y-5">
            {groups.map((group) => (
              <div key={(group.subgroup ?? "default") + category}>
                {group.subgroup && (
                  <div className="mb-2 text-[11px] font-semibold uppercase tracking-wider text-[var(--soft)]">
                    {group.subgroup}
                  </div>
                )}
                <ul className="space-y-1.5 border-l border-[var(--rule)]">
                  {group.docs.map((doc) => {
                    const isActive = active === doc.slugPath;
                    return (
                      <li key={doc.slugPath}>
                        <Link
                          href={`/docs/${doc.slugPath}`}
                          className={clsx(
                            "block break-words -ml-px border-l py-1.5 pl-3 text-[13px] leading-snug transition",
                            isActive
                              ? "border-accent text-accent font-medium"
                              : "border-transparent text-[var(--muted)] hover:text-[var(--fg)] hover:border-[var(--rule-strong)]",
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
      </div>
    </div>
  );
}
