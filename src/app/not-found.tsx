import Link from "next/link";

export default function NotFound() {
  return (
    <div className="mx-auto max-w-2xl px-4 sm:px-6 py-32">
      <p className="eyebrow">404</p>
      <h1 className="h-section mt-4">That page does not exist</h1>
      <p className="subtitle mt-4">
        The link may be wrong, or the page may have moved. Try the
        documentation index or the search page.
      </p>
      <div className="mt-10 flex flex-wrap items-center gap-4">
        <Link href="/" className="btn btn-primary">
          Back home
        </Link>
        <Link
          href="/docs"
          className="text-base text-[var(--fg)] hover:text-accent underline underline-offset-4 decoration-[var(--rule)] hover:decoration-accent transition"
        >
          Browse docs
        </Link>
        <Link
          href="/docs/search"
          className="text-base text-[var(--fg)] hover:text-accent underline underline-offset-4 decoration-[var(--rule)] hover:decoration-accent transition"
        >
          Search docs
        </Link>
      </div>
    </div>
  );
}
