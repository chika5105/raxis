"use client";

import Link from "next/link";
import { useEffect } from "react";

interface Props {
  error: Error & { digest?: string };
  reset: () => void;
}

export default function Error({ error, reset }: Props) {
  useEffect(() => {
    console.error(error);
  }, [error]);

  return (
    <div className="flex min-h-[60vh] flex-col items-center justify-center px-6 text-center">
      <p className="eyebrow mb-4">Something went wrong</p>
      <h2 className="h-section mb-6 max-w-md">
        An unexpected error occurred
      </h2>
      <p className="subtitle mb-10 max-w-sm">
        {error.message || "The page encountered an error. Try refreshing or go back home."}
      </p>
      <div className="flex flex-wrap items-center justify-center gap-4">
        <button
          type="button"
          onClick={reset}
          className="btn btn-primary"
        >
          Try again
        </button>
        <Link href="/" className="btn btn-ghost">
          Go home
        </Link>
      </div>
      {error.digest && (
        <p className="mt-8 text-xs font-mono text-[var(--soft)]">
          Error ID: {error.digest}
        </p>
      )}
    </div>
  );
}
