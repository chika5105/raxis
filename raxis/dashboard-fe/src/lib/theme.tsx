// ─────────────────────────────────────────────────────────────────
// Theme context — light / dark with operator-controlled persistence
// ─────────────────────────────────────────────────────────────────
//
// UI design: dark mode default, operator readability is
// non-negotiable.
//
// Operator UX contract:
//
//   * Dark is the default.
//   * Toggle preference is persisted to `localStorage.theme`
//     ("dark" or "light"). The persisted value wins on every load.
//   * On a first visit (nothing in `localStorage`), the system
//     `prefers-color-scheme: light` media query is honoured.
//   * As long as the operator has NOT explicitly chosen a mode,
//     system-level theme changes (e.g. macOS Night Shift schedule
//     flipping their preference at sundown) are mirrored live.
//     Once they click the toggle, system events stop overriding
//     their choice.
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

function readSystemTheme(): Theme {
  if (!isBrowser() || typeof window.matchMedia !== "function") {
    return "dark";
  }
  return window.matchMedia("(prefers-color-scheme: light)").matches
    ? "light"
    : "dark";
}

function resolveInitialTheme(): {
  theme: Theme;
  hasExplicitPreference: boolean;
} {
  const stored = readStoredTheme();
  if (stored) return { theme: stored, hasExplicitPreference: true };
  return { theme: readSystemTheme(), hasExplicitPreference: false };
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

  // Track the system preference *only* while the operator has no
  // explicit choice — clicking the toggle pins them to a value
  // and we stop reacting to OS-level changes from that point on.
  useEffect(() => {
    if (!isBrowser() || typeof window.matchMedia !== "function") return;
    if (hasExplicitPreference) return;
    const mq = window.matchMedia("(prefers-color-scheme: light)");
    const onChange = (e: MediaQueryListEvent) => {
      setState({
        theme: e.matches ? "light" : "dark",
        hasExplicitPreference: false,
      });
    };
    // Safari < 14 only supports the deprecated `addListener` API.
    if (typeof mq.addEventListener === "function") {
      mq.addEventListener("change", onChange);
      return () => mq.removeEventListener("change", onChange);
    }
    mq.addListener(onChange);
    return () => mq.removeListener(onChange);
  }, [hasExplicitPreference]);

  // Honour `localStorage.theme` writes from another tab so a
  // toggle in one operator window mirrors into siblings.
  useEffect(() => {
    if (!isBrowser()) return;
    const onStorage = (e: StorageEvent) => {
      if (e.key !== STORAGE_KEY) return;
      if (e.newValue === "dark" || e.newValue === "light") {
        setState({ theme: e.newValue, hasExplicitPreference: true });
      } else if (e.newValue === null) {
        // Another tab cleared the preference — fall back to system.
        setState({
          theme: readSystemTheme(),
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
