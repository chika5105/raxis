"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import Link from "next/link";
import MiniSearch from "minisearch";

interface DocMeta {
  id: string;
  slug: string;
  title: string;
  category: string;
  snippet: string;
}

interface IndexFile {
  index: any;
  meta: DocMeta[];
  builtAt?: string;
  count?: number;
}

interface SearchResult extends DocMeta {
  score: number;
  matched: string[];
}

const MS_OPTS = {
  fields: ["title", "headings", "body", "slug"],
  storeFields: ["title", "category", "snippet", "slug", "headings"],
  searchOptions: {
    boost: { title: 4, headings: 2, slug: 1.5 },
    prefix: true,
    fuzzy: 0.15,
  },
};

export function SearchClient() {
  const inputRef = useRef<HTMLInputElement>(null);
  const [q, setQ] = useState("");
  const [state, setState] = useState<"idle" | "loading" | "ready" | "error">("idle");
  const [error, setError] = useState<string | null>(null);
  const [ms, setMs] = useState<MiniSearch | null>(null);
  const [count, setCount] = useState(0);

  useEffect(() => {
    setState("loading");
    fetch("/search-index.json", { cache: "force-cache" })
      .then(async (r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return (await r.json()) as IndexFile;
      })
      .then((data) => {
        if (!data.index) {
          setState("ready");
          setMs(null);
          setCount(data.count ?? 0);
          return;
        }
        const restored = MiniSearch.loadJS(data.index, MS_OPTS as any);
        setMs(restored);
        setCount(data.count ?? data.meta?.length ?? 0);
        setState("ready");
      })
      .catch((err) => {
        setState("error");
        setError(String(err?.message ?? err));
      });
  }, []);

  useEffect(() => {
    inputRef.current?.focus();
  }, [state]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        inputRef.current?.focus();
        inputRef.current?.select();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const results: SearchResult[] = useMemo(() => {
    if (!ms || !q.trim()) return [];
    const raw = ms.search(q.trim());
    return raw.slice(0, 30).map((r: any) => ({
      id: r.id,
      slug: r.slug,
      title: r.title,
      category: r.category,
      snippet: r.snippet,
      score: r.score,
      matched: r.terms ?? [],
    }));
  }, [ms, q]);

  return (
    <div>
      <div className="relative">
        <svg
          aria-hidden
          className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-[var(--muted)]"
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
        <input
          ref={inputRef}
          type="search"
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder="Search the docs"
          className="w-full rounded-md border border-[var(--rule)] bg-[var(--bg)] py-2.5 pl-10 pr-14 text-[15px] text-[var(--fg)] placeholder:text-[var(--muted)] focus:outline-none focus:border-accent transition"
          spellCheck={false}
          autoComplete="off"
          aria-label="Search documentation"
        />
        <kbd className="hidden sm:inline-flex absolute right-3 top-1/2 -translate-y-1/2 items-center font-mono text-[11px] text-[var(--muted)]">
          ⌘K
        </kbd>
      </div>

      <div className="mt-3 text-xs text-[var(--muted)]">
        {state === "loading" && "Loading index…"}
        {state === "error" && (
          <span className="text-red-500">Failed to load index: {error}</span>
        )}
        {state === "ready" && q.trim() === "" && (
          <span>{count} documents indexed.</span>
        )}
        {state === "ready" && q.trim() !== "" && (
          <span>
            {results.length} {results.length === 1 ? "result" : "results"} for{" "}
            <span className="text-[var(--fg)]">&ldquo;{q.trim()}&rdquo;</span>
          </span>
        )}
      </div>

      {state === "ready" && q.trim() !== "" && results.length > 0 && (
        <ol className="mt-6 divide-y divide-[var(--rule)] border-y border-[var(--rule)]">
          {results.map((r) => (
            <li key={r.id}>
              <Link
                href={`/docs/${r.slug}`}
                className="block py-4 group"
              >
                <div className="flex items-baseline justify-between gap-3">
                  <h3 className="text-[15px] font-semibold text-[var(--fg)] group-hover:text-accent transition">
                    <Highlight text={r.title} terms={r.matched} />
                  </h3>
                  <span className="text-xs text-[var(--muted)] shrink-0">{r.category}</span>
                </div>
                <div className="mt-0.5 font-mono text-[12px] text-[var(--muted)] truncate">
                  /{r.slug}
                </div>
                {r.snippet && (
                  <p className="mt-2 text-[14px] text-[var(--muted)] leading-relaxed line-clamp-2">
                    <Highlight text={r.snippet} terms={r.matched} />
                  </p>
                )}
              </Link>
            </li>
          ))}
        </ol>
      )}

      {state === "ready" && q.trim() !== "" && results.length === 0 && (
        <div className="mt-8 text-sm text-[var(--muted)]">
          No matches. Try shorter terms, a different spelling, or browse the index.
        </div>
      )}

      {state === "ready" && q.trim() === "" && (
        <div className="mt-6 flex flex-wrap gap-2">
          {["audit chain", "credential proxy", "escalation", "panel review", "lampson protection"].map((label) => (
            <button
              key={label}
              type="button"
              onClick={() => setQ(label)}
              className="rounded-md border border-[var(--rule)] px-2.5 py-1 text-xs text-[var(--muted)] hover:text-[var(--fg)] hover:border-[var(--fg)] transition"
            >
              {label}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

function Highlight({ text, terms }: { text: string; terms: string[] }) {
  if (!terms?.length) return <>{text}</>;
  const escaped = terms
    .filter(Boolean)
    .map((t) => t.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"));
  if (escaped.length === 0) return <>{text}</>;
  const re = new RegExp(`(${escaped.join("|")})`, "ig");
  const parts = text.split(re);
  return (
    <>
      {parts.map((p, i) =>
        re.test(p) ? (
          <mark
            key={i}
            className="rounded-sm bg-accent-soft text-[var(--fg)] px-0.5"
          >
            {p}
          </mark>
        ) : (
          <span key={i}>{p}</span>
        ),
      )}
    </>
  );
}
