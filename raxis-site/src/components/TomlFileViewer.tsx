"use client";

import { useState } from "react";

interface Props {
  filename: string;
  content: string;
  defaultOpen?: boolean;
}

function FileIcon() {
  return (
    <svg
      width="14"
      height="14"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.75"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      className="shrink-0 text-[var(--soft)]"
    >
      <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
      <polyline points="14 2 14 8 20 8" />
    </svg>
  );
}

function ChevronIcon({ open }: { open: boolean }) {
  return (
    <svg
      width="14"
      height="14"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2.5"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      className="shrink-0 text-[var(--soft)] transition-transform duration-200"
      style={{ transform: open ? "rotate(180deg)" : "rotate(0deg)" }}
    >
      <path d="M6 9l6 6 6-6" />
    </svg>
  );
}

export function TomlFileViewer({ filename, content, defaultOpen = false }: Props) {
  const [open, setOpen] = useState(defaultOpen);

  return (
    <div className="border border-[var(--rule)] rounded-[var(--radius-md)] overflow-hidden">
      <button
        type="button"
        onClick={() => setOpen(!open)}
        aria-expanded={open}
        className="w-full flex items-center gap-2.5 px-4 py-3 bg-[var(--surface)] hover:bg-[var(--accent-soft)] transition text-left select-none"
      >
        <FileIcon />
        <span className="font-mono text-sm font-medium text-[var(--fg)] flex-1 truncate">
          {filename}
        </span>
        <span className="text-[0.65rem] font-semibold uppercase tracking-widest text-[var(--soft)] bg-[var(--code-bg)] border border-[var(--rule)] rounded px-1.5 py-0.5 shrink-0">
          TOML
        </span>
        <ChevronIcon open={open} />
      </button>

      {/* Grid row trick — smooth height animation without max-height jank */}
      <div
        className="grid transition-[grid-template-rows] duration-200 ease-in-out"
        style={{ gridTemplateRows: open ? "1fr" : "0fr" }}
      >
        <div className="overflow-hidden">
          <pre
            className="overflow-x-auto m-0 p-4 text-[0.8125rem] leading-relaxed border-t border-[var(--rule)]"
            style={{
              background: "var(--code-bg)",
              fontFamily: "var(--font-mono), ui-monospace, SFMono-Regular, Menlo, monospace",
              color: "var(--fg)",
            }}
          >
            <code>{content}</code>
          </pre>
        </div>
      </div>
    </div>
  );
}
