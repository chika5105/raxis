import Link from "next/link";

export default function NotFound() {
  return (
    <div className="mx-auto max-w-2xl px-4 sm:px-6 py-24 text-center">
      <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">FAIL_NOT_FOUND</p>
      <h1 className="mt-3 text-4xl sm:text-5xl font-semibold tracking-[-0.02em]">
        The kernel could not admit that path.
      </h1>
      <p className="mt-4 text-[var(--muted)]">
        Coarse rejection code — no specific rule disclosed (R-10). Try the documentation index, or search for what you
        were looking for.
      </p>
      <div className="mt-8 flex flex-wrap items-center justify-center gap-3">
        <Link
          href="/"
          className="inline-flex h-10 items-center justify-center rounded-md bg-accent px-5 text-sm font-medium text-white hover:bg-accent-strong transition"
        >
          Back home
        </Link>
        <Link
          href="/docs"
          className="inline-flex h-10 items-center justify-center rounded-md border border-[var(--rule)] px-5 text-sm font-medium text-[var(--fg)] hover:border-[var(--fg)] transition"
        >
          Browse docs
        </Link>
        <Link
          href="/docs/search"
          className="inline-flex h-10 items-center justify-center rounded-md border border-[var(--rule)] px-5 text-sm font-medium text-[var(--fg)] hover:border-[var(--fg)] transition"
        >
          Search docs
        </Link>
      </div>
    </div>
  );
}
