/** @type {import('tailwindcss').Config} */
export default {
  darkMode: "class",
  content: [
    "./index.html",
    "./src/**/*.{ts,tsx,js,jsx,html}",
  ],
  theme: {
    extend: {
      colors: {
        // Operator tooling palette: dense, calm, dark-mode
        // first. The "ink" family is the foreground; "panel"
        // is layered backgrounds; "edge" is borders + dividers.
        // Status colors mirror the kernel state vocabulary
        // (Pending/Running/Completed/Failed/Blocked).
        ink:    { DEFAULT: "#e6e8eb", muted: "#a8b1bc", subtle: "#7d8892" },
        panel:  { DEFAULT: "#0d1117", raised: "#161b22", high:   "#1f2733" },
        edge:   { DEFAULT: "#222a36", strong:  "#2e3849" },
        accent: { DEFAULT: "#3a86ff", strong:  "#1f6feb" },
        ok:     { DEFAULT: "#2ea043", muted:   "#1c5b2c" },
        warn:   { DEFAULT: "#d29922", muted:   "#6b4d10" },
        bad:    { DEFAULT: "#f85149", muted:   "#7d1d1d" },
        info:   { DEFAULT: "#58a6ff", muted:   "#1f4d80" },
        block:  { DEFAULT: "#a371f7", muted:   "#3a2762" },
      },
      fontFamily: {
        sans: [
          "Inter",
          "ui-sans-serif",
          "system-ui",
          "-apple-system",
          "BlinkMacSystemFont",
          "Segoe UI",
          "Helvetica",
          "Arial",
          "sans-serif",
        ],
        mono: [
          "JetBrains Mono",
          "ui-monospace",
          "SFMono-Regular",
          "Menlo",
          "Monaco",
          "Consolas",
          "monospace",
        ],
      },
      fontSize: {
        // Slightly smaller defaults because operator tools
        // need information density.
        xs: ["0.72rem", { lineHeight: "1rem" }],
        sm: ["0.82rem", { lineHeight: "1.15rem" }],
        base: ["0.92rem", { lineHeight: "1.3rem" }],
        lg: ["1.05rem", { lineHeight: "1.45rem" }],
        xl: ["1.25rem", { lineHeight: "1.7rem" }],
      },
      boxShadow: {
        soft: "0 1px 2px 0 rgba(0,0,0,0.4)",
        ring: "0 0 0 1px rgba(58,134,255,0.45)",
      },
      animation: {
        pulseDot: "pulseDot 1.6s ease-in-out infinite",
      },
      keyframes: {
        pulseDot: {
          "0%, 100%": { opacity: "1", transform: "scale(1)" },
          "50%":      { opacity: "0.45", transform: "scale(0.85)" },
        },
      },
    },
  },
  plugins: [],
};
