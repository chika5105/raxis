"use client";

import { useEffect } from "react";

interface Props {
  error: Error & { digest?: string };
  reset: () => void;
}

export default function GlobalError({ error, reset }: Props) {
  useEffect(() => {
    console.error(error);
  }, [error]);

  return (
    <html lang="en">
      <body
        style={{
          margin: 0,
          fontFamily:
            "-apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif",
          background: "#fafaf9",
          color: "#171717",
          display: "flex",
          minHeight: "100dvh",
          alignItems: "center",
          justifyContent: "center",
          padding: "2rem",
          textAlign: "center",
          flexDirection: "column",
          gap: "1.5rem",
        }}
      >
        <p
          style={{
            fontSize: "0.875rem",
            fontWeight: 600,
            letterSpacing: "0.06em",
            textTransform: "uppercase",
            color: "#0a7289",
          }}
        >
          Critical error
        </p>
        <h1
          style={{
            fontSize: "clamp(1.875rem, 3vw + 1rem, 2.75rem)",
            fontWeight: 600,
            margin: 0,
            maxWidth: "32rem",
          }}
        >
          The application failed to load
        </h1>
        <p style={{ color: "#525252", maxWidth: "28rem", lineHeight: 1.65 }}>
          {error.message ||
            "A critical error prevented the page from loading. Please try again."}
        </p>
        <div style={{ display: "flex", gap: "1rem", flexWrap: "wrap", justifyContent: "center" }}>
          <button
            type="button"
            onClick={reset}
            style={{
              padding: "12px 24px",
              background: "#0a7289",
              color: "#fff",
              border: "none",
              borderRadius: "10px",
              fontSize: "1rem",
              fontWeight: 600,
              cursor: "pointer",
            }}
          >
            Try again
          </button>
          {/*
           * Intentional native <a>: global-error.tsx renders above the root
           * layout when the app shell itself crashes. next/link relies on the
           * client router being mounted, which is not guaranteed in this
           * boundary — a hard navigation is the correct recovery affordance.
           */}
          {/* eslint-disable-next-line @next/next/no-html-link-for-pages -- see comment above */}
          <a
            href="/"
            style={{
              padding: "12px 24px",
              background: "#fff",
              color: "#171717",
              border: "1px solid #e5e5e5",
              borderRadius: "10px",
              fontSize: "1rem",
              fontWeight: 600,
              textDecoration: "none",
            }}
          >
            Go home
          </a>
        </div>
        {error.digest && (
          <p style={{ fontSize: "0.75rem", fontFamily: "monospace", color: "#737373" }}>
            Error ID: {error.digest}
          </p>
        )}
      </body>
    </html>
  );
}
