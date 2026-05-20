// ─────────────────────────────────────────────────────────────────
// Theme context — light / dark with operator-controlled persistence
// ─────────────────────────────────────────────────────────────────
//
// UI design: light mode default, operator readability is
// non-negotiable.
//
// Operator UX contract:
//
//   * Light is the default.
//   * Toggle preference is persisted to `localStorage.theme`
//     ("dark" or "light"). The persisted value wins on every load.
//   * On a first visit (nothing in `localStorage`), the dashboard
//     starts in light mode regardless of the OS colour scheme. This
//     keeps shared demos, screenshots, and fresh operator sessions
//     predictable.
//
// FOUC is handled by an inline bootstrap script in `index.html`
// that applies the same resolution rules to <html> before React
// mounts — see comment block in `index.html`.

import {
  useCallback,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";

import { ThemeContext, type Theme, type ThemeContextValue } from "./theme-context";

// Re-export the public types so existing `from "@/lib/theme"`
// imports of `Theme` / `ThemeContextValue` continue to compile.
export type { Theme, ThemeContextValue };

// ─────────────────────────────────────────────────────────────────
// Storage / browser helpers
// ─────────────────────────────────────────────────────────────────

const STORAGE_KEY = "theme";
const DEFAULT_THEME: Theme = "light";
const META_THEME_DARK = "#0d1117";
const META_THEME_LIGHT = "#fafaf9";

const isBrowser = (): boolean =>
  typeof window !== "undefined" && typeof document !== "undefined";

function readStoredTheme(): Theme | null {
  if (!isBrowser()) return null;
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    return raw === "dark" || raw === "light" ? raw : null;
  } catch {
    // Private-mode browsers can throw on access.
    return null;
  }
}

function writeStoredTheme(theme: Theme): void {
  if (!isBrowser()) return;
  try {
    window.localStorage.setItem(STORAGE_KEY, theme);
  } catch {
    // Storage may be blocked; in-memory state remains correct.
  }
}

function resolveInitialTheme(): {
  theme: Theme;
  hasExplicitPreference: boolean;
} {
  const stored = readStoredTheme();
  if (stored) return { theme: stored, hasExplicitPreference: true };
  return { theme: DEFAULT_THEME, hasExplicitPreference: false };
}

function applyThemeToDocument(theme: Theme): void {
  if (!isBrowser()) return;
  const root = document.documentElement;
  if (theme === "dark") {
    root.classList.add("dark");
    root.classList.remove("light");
  } else {
    root.classList.remove("dark");
    root.classList.add("light");
  }
  // Mirror to the mobile viewport meta-tag so iOS / Android chrome
  // matches the canvas background.
  const meta = document.querySelector('meta[name="theme-color"]');
  if (meta) {
    meta.setAttribute(
      "content",
      theme === "dark" ? META_THEME_DARK : META_THEME_LIGHT,
    );
  }
}

// ─────────────────────────────────────────────────────────────────
// Provider
// ─────────────────────────────────────────────────────────────────

interface ThemeProviderProps {
  children: ReactNode;
}

export function ThemeProvider({ children }: ThemeProviderProps) {
  // SSR-safe initial state. On the client this runs synchronously
  // before paint — the inline bootstrap in index.html has already
  // set the class, so the very first render matches the DOM.
  const [{ theme, hasExplicitPreference }, setState] = useState(() =>
    resolveInitialTheme(),
  );

  // Keep <html> in sync whenever the theme changes (incl. via
  // cross-tab `storage` events further down).
  useEffect(() => {
    applyThemeToDocument(theme);
  }, [theme]);

  // Honour `localStorage.theme` writes from another tab so a
  // toggle in one operator window mirrors into siblings.
  useEffect(() => {
    if (!isBrowser()) return;
    const onStorage = (e: StorageEvent) => {
      if (e.key !== STORAGE_KEY) return;
      if (e.newValue === "dark" || e.newValue === "light") {
        setState({ theme: e.newValue, hasExplicitPreference: true });
      } else if (e.newValue === null) {
        // Another tab cleared the preference — fall back to the
        // dashboard's deterministic default.
        setState({
          theme: DEFAULT_THEME,
          hasExplicitPreference: false,
        });
      }
    };
    window.addEventListener("storage", onStorage);
    return () => window.removeEventListener("storage", onStorage);
  }, []);

  const setTheme = useCallback((next: Theme) => {
    writeStoredTheme(next);
    setState({ theme: next, hasExplicitPreference: true });
  }, []);

  const toggleTheme = useCallback(() => {
    setState((prev) => {
      const next: Theme = prev.theme === "dark" ? "light" : "dark";
      writeStoredTheme(next);
      return { theme: next, hasExplicitPreference: true };
    });
  }, []);

  const value = useMemo<ThemeContextValue>(
    () => ({ theme, setTheme, toggleTheme, hasExplicitPreference }),
    [theme, setTheme, toggleTheme, hasExplicitPreference],
  );

  return (
    <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>
  );
}
