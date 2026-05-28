"use client";

import { useState } from "react";

const LOOM_ID = "a9e5673f410542bcb09b8ce7813e240c";
const LOOM_URL = `https://www.loom.com/share/${LOOM_ID}`;
const LOOM_EMBED_URL = `https://www.loom.com/embed/${LOOM_ID}`;
const LOOM_POSTER =
  "https://cdn.loom.com/sessions/thumbnails/a9e5673f410542bcb09b8ce7813e240c-8c47717da2a08ec1-full-play.jpg";

export function DemoPlayer() {
  const [loaded, setLoaded] = useState(false);

  return (
    <div className="min-w-0 max-w-full overflow-hidden rounded-2xl border border-[var(--rule)] bg-[var(--surface)] shadow-[var(--shadow-soft)]">
      <div className="relative aspect-video bg-black">
        {loaded ? (
          <iframe
            src={LOOM_EMBED_URL}
            title="RAXIS demo video"
            className="h-full w-full"
            allow="fullscreen; picture-in-picture"
            allowFullScreen
          />
        ) : (
          <>
            {/* eslint-disable-next-line @next/next/no-img-element */}
            <img
              src={LOOM_POSTER}
              alt="RAXIS demo video preview"
              className="block h-full w-full object-cover"
            />
            <div className="absolute inset-0 flex items-center justify-center bg-black/20">
              <button
                type="button"
                onClick={() => setLoaded(true)}
                className="inline-flex min-h-12 items-center rounded-full border border-white/25 bg-white px-6 py-3 text-base font-semibold text-neutral-950 shadow-lg transition hover:scale-[1.02] hover:bg-neutral-100 focus:outline-none focus:ring-2 focus:ring-white focus:ring-offset-2 focus:ring-offset-black"
                aria-label="Play the embedded RAXIS demo video"
              >
                Play demo
              </button>
            </div>
          </>
        )}
      </div>
      <div className="flex flex-wrap items-center justify-between gap-3 border-t border-[var(--rule)] px-4 py-3 text-sm text-[var(--muted)]">
        <span>Embedded Loom demo</span>
        <a
          href={LOOM_URL}
          target="_blank"
          rel="noopener noreferrer"
          className="font-semibold text-accent underline-offset-4 hover:underline"
        >
          Open on Loom
        </a>
      </div>
    </div>
  );
}
