// Theme context + consumer hook.
//
// Split out from `theme.tsx` (which holds the `ThemeProvider`
// component) so that the provider file only exports React
// components. That keeps Vite's React Fast Refresh boundary clean
// (`react-refresh/only-export-components`): a file that exports
// both a component and a hook forces a full module reload on
// every edit, defeating HMR for the provider.

import { createContext, useContext } from "react";

export type Theme = "dark" | "light";

export interface ThemeContextValue {
  /** Currently-applied theme. */
  theme: Theme;
  /** Explicitly pin the theme (also persists to localStorage). */
  setTheme: (next: Theme) => void;
  /** Flip the theme once. */
  toggleTheme: () => void;
  /**
   * `true` when the current value was chosen by the operator;
   * `false` when it is the dashboard's deterministic default.
   * Exposed mainly for tests and for chrome that wants to surface
   * an explicit "use default" affordance later.
   */
  hasExplicitPreference: boolean;
}

export const ThemeContext = createContext<ThemeContextValue | null>(null);

export function useTheme(): ThemeContextValue {
  const ctx = useContext(ThemeContext);
  if (!ctx) {
    throw new Error(
      "useTheme() called outside <ThemeProvider>. Wrap your tree " +
        "in `<ThemeProvider>` (see src/main.tsx).",
    );
  }
  return ctx;
}
