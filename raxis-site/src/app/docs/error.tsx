"use client";

import { useEffect } from "react";
import Link from "next/link";

interface Props {
  error: Error & { digest?: string };
  reset: () => void;
}

export default function DocsError({ error, reset }: Props) {
  useEffect(() => {
    console.error(error);
  }, [error]);

  return (
    <div className="w-full px-6 xl:px-12 py-20 flex flex-col items-start gap-6 max-w-2xl">
      <p className="eyebrow">Documentation error</p>
      <h2 className="h-section">Failed to load this page</h2>
      <p className="subtitle">
        {error.message || "Something went wrong while loading the documentation."}
      </p>
      <div className="flex flex-wrap gap-4">
        <button
          type="button"
          onClick={reset}
          className="btn btn-primary"
        >
          Try again
        </button>
        <Link href="/docs" className="btn btn-ghost">
          Back to docs index
        </Link>
      </div>
      {error.digest && (
        <p className="text-xs font-mono text-[var(--soft)]">
          Error ID: {error.digest}
        </p>
      )}
    </div>
  );
}
