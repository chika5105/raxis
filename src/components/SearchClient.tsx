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
  const [meta, setMeta] = useState<DocMeta[]>([]);
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
          setMeta(data.meta ?? []);
          setCount(data.count ?? 0);
          return;
        }
        const restored = MiniSearch.loadJS(data.index, MS_OPTS as any);
        setMs(restored);
        setMeta(data.meta ?? []);
        setCount(data.count ?? data.meta?.length ?? 0);
        setState("ready");
      })
      .catch((err) => {
        setState("error");
        setError(String(err?.message ?? err));
      });
  }, []);

  // Autofocus the input on mount.
  useEffect(() => {
    inputRef.current?.focus();
  }, [state]);

  // Cmd/Ctrl-K to focus.
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
          className="pointer-events-none absolute left-4 top-1/2 -translate-y-1/2 text-[var(--muted)]"
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
          placeholder="Search 12 invariants, intent admission, credential proxies, scenarios…"
          className="w-full rounded-lg border border-[var(--rule)] bg-[var(--card)] py-3 pl-11 pr-16 text-sm text-[var(--fg)] placeholder:text-[var(--muted)] focus:outline-none focus:border-accent focus:ring-2 focus:ring-accent/20 transition"
          spellCheck={false}
          autoComplete="off"
          aria-label="Search documentation"
        />
        <kbd className="hidden sm:inline-flex absolute right-3 top-1/2 -translate-y-1/2 items-center rounded border border-[var(--rule)] bg-[var(--bg)] px-1.5 py-0.5 font-mono text-[10px] text-[var(--muted)]">
          ⌘K
        </kbd>
      </div>

      <div className="mt-3 text-xs text-[var(--muted)]">
        {state === "loading" && "Loading index…"}
        {state === "error" && (
          <span className="text-red-500">Failed to load index: {error}</span>
        )}
        {state === "ready" && q.trim() === "" && (
          <span>{count} documents indexed. Try a query above, or browse by category.</span>
        )}
        {state === "ready" && q.trim() !== "" && (
          <span>
            {results.length} {results.length === 1 ? "result" : "results"} for{" "}
            <strong className="text-[var(--fg)]">"{q.trim()}"</strong>
          </span>
        )}
      </div>

      {state === "ready" && q.trim() !== "" && results.length > 0 && (
        <ol className="mt-6 space-y-3">
          {results.map((r) => (
            <li key={r.id}>
              <Link
                href={`/docs/${r.slug}`}
                className="block rounded-lg border border-[var(--card-rule)] bg-[var(--card)] p-4 hover:border-accent transition"
              >
                <div className="flex items-baseline justify-between gap-3">
                  <h3 className="font-medium tracking-tight">
                    <Highlight text={r.title} terms={r.matched} />
                  </h3>
                  <span className="font-mono text-[10px] uppercase tracking-wider text-accent shrink-0">
                    {r.category}
                  </span>
                </div>
                <div className="mt-1 font-mono text-[11px] text-[var(--muted)] truncate">/{r.slug}</div>
                {r.snippet && (
                  <p className="mt-2 text-sm text-[var(--muted)] leading-relaxed line-clamp-3">
                    <Highlight text={r.snippet} terms={r.matched} />
                  </p>
                )}
              </Link>
            </li>
          ))}
        </ol>
      )}

      {state === "ready" && q.trim() !== "" && results.length === 0 && (
        <div className="mt-8 rounded-xl border border-dashed border-[var(--rule)] p-6 text-center text-sm text-[var(--muted)]">
          No matches. Try shorter terms, a different spelling, or check the category index.
        </div>
      )}

      {state === "ready" && q.trim() === "" && (
        <div className="mt-6 grid gap-2 sm:grid-cols-2">
          {[
            ["12 invariants", "12 invariants"],
            ["credential proxy", "credential proxy"],
            ["audit chain", "audit chain"],
            ["escalation", "escalation"],
            ["lampson protection", "lampson protection"],
            ["panel review", "panel review"],
          ].map(([label, query]) => (
            <button
              key={label}
              type="button"
              onClick={() => setQ(query)}
              className="rounded-lg border border-[var(--card-rule)] bg-[var(--card)] p-3 text-left text-sm hover:border-accent transition"
            >
              <span className="text-[var(--muted)]">Try </span>
              <span className="font-medium text-accent">{label}</span>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

function Highlight({ text, terms }: { text: string; terms: string[] }) {
  if (!terms?.length) return <>{text}</>;
  // Build a single regex of all whole-word-ish term matches (case-insensitive).
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
