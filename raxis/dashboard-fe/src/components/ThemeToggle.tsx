// ─────────────────────────────────────────────────────────────────
// ThemeToggle — single-button light / dark switch
// ─────────────────────────────────────────────────────────────────
//
// Lives in the dashboard chrome (currently the top-bar in
// <Shell>). The button shows the icon for the mode you'll get
// *after* the click — sun when you're in dark (click to lighten),
// moon when you're in light (click to darken). This matches the
// affordance pattern used by GitHub, Vercel, Linear, etc.
//
// Placement note for sibling refactors: this is a self-contained
// component. If `worker/dashboard-clickability-nav` restructures
// the header, the toggle can be re-located by changing a single
// JSX line in <Shell> — no internal coupling.

import clsx from "clsx";

import { useTheme } from "@/lib/theme-context";

interface ThemeToggleProps {
  className?: string;
}

export function ThemeToggle({ className }: ThemeToggleProps) {
  const { theme, toggleTheme } = useTheme();
  const nextLabel = theme === "dark" ? "light" : "dark";
  return (
    <button
      type="button"
      onClick={toggleTheme}
      title={`Switch to ${nextLabel} mode`}
      aria-label={`Switch to ${nextLabel} mode`}
      // We deliberately do NOT advertise the `pressed` state via
      // aria-pressed because that misrepresents the affordance —
      // the button isn't a stateful toggle in the sense AT
      // expects (e.g. "filter on / filter off"); it's a single
      // action that swaps the global theme.
      className={clsx(
        "inline-flex items-center justify-center w-7 h-7 rounded-md",
        "border border-edge-strong bg-panel-raised text-ink-muted",
        "hover:bg-panel-high hover:text-ink hover:border-accent",
        "focus:outline-none focus:ring-1 focus:ring-accent focus:border-accent",
        "transition-colors",
        className,
      )}
    >
      {theme === "dark" ? <SunIcon /> : <MoonIcon />}
    </button>
  );
}

// ─────────────────────────────────────────────────────────────────
// Icons — inline SVG keeps the bundle free of an icon dep.
//
// Both glyphs use `currentColor` so they pick up the button's
// text color through the theme tokens.
// ─────────────────────────────────────────────────────────────────

function SunIcon() {
  return (
    <svg
      width="14"
      height="14"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <circle cx="12" cy="12" r="4" />
      <path d="M12 2v2" />
      <path d="M12 20v2" />
      <path d="m4.93 4.93 1.41 1.41" />
      <path d="m17.66 17.66 1.41 1.41" />
      <path d="M2 12h2" />
      <path d="M20 12h2" />
      <path d="m6.34 17.66-1.41 1.41" />
      <path d="m19.07 4.93-1.41 1.41" />
    </svg>
  );
}

function MoonIcon() {
  return (
    <svg
      width="14"
      height="14"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" />
    </svg>
  );
}
