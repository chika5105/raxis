"use client";

import { useState } from "react";

interface Heading {
  depth: 2 | 3;
  text: string;
  id: string;
}

interface Props {
  headings: Heading[];
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

export function OnThisPage({ headings }: Props) {
  const [open, setOpen] = useState(true);

  if (!headings.length) return null;

  return (
    <nav aria-label="On this page" className="text-sm">
      <button
        type="button"
        onClick={() => setOpen(!open)}
        className="w-full flex items-center gap-1.5 mb-3 group"
        aria-expanded={open}
      >
        <span className="flex-1 text-left text-xs font-semibold uppercase tracking-wider text-[var(--muted)] group-hover:text-[var(--fg)] transition">
          On this page
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
        </div>
      </div>
    </nav>
  );
}
