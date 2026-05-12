/** @type {import('tailwindcss').Config} */
//
// Color tokens are sourced from CSS custom properties defined in
// `src/styles/global.css` (see `:root` for light and `:root.dark`
// for dark). The `rgb(var(--c-x) / <alpha-value>)` pattern lets
// Tailwind opacity utilities like `bg-accent/30` keep working
// without exploding the token surface area.
//
// Operator-tooling semantic palette:
//   * ink     — foreground text (DEFAULT / muted / subtle)
//   * panel   — layered backgrounds (DEFAULT / raised / high)
//   * edge    — borders + dividers (DEFAULT / strong)
//   * accent  — primary actionable color
//   * ok/warn/bad/info/block — kernel FSM status families
//                              (DEFAULT for text/border,
//                               muted for tinted backgrounds)
export default {
  darkMode: "class",
  content: [
    "./index.html",
    "./src/**/*.{ts,tsx,js,jsx,html}",
  ],
  theme: {
    extend: {
      colors: {
        ink: {
          DEFAULT: "rgb(var(--c-ink) / <alpha-value>)",
          muted:   "rgb(var(--c-ink-muted) / <alpha-value>)",
          subtle:  "rgb(var(--c-ink-subtle) / <alpha-value>)",
        },
        panel: {
          DEFAULT: "rgb(var(--c-panel) / <alpha-value>)",
          raised:  "rgb(var(--c-panel-raised) / <alpha-value>)",
          high:    "rgb(var(--c-panel-high) / <alpha-value>)",
        },
        edge: {
          DEFAULT: "rgb(var(--c-edge) / <alpha-value>)",
          strong:  "rgb(var(--c-edge-strong) / <alpha-value>)",
        },
        accent: {
          DEFAULT: "rgb(var(--c-accent) / <alpha-value>)",
          strong:  "rgb(var(--c-accent-strong) / <alpha-value>)",
        },
        ok: {
          DEFAULT: "rgb(var(--c-ok) / <alpha-value>)",
          muted:   "rgb(var(--c-ok-muted) / <alpha-value>)",
        },
        warn: {
          DEFAULT: "rgb(var(--c-warn) / <alpha-value>)",
          muted:   "rgb(var(--c-warn-muted) / <alpha-value>)",
        },
        bad: {
          DEFAULT: "rgb(var(--c-bad) / <alpha-value>)",
          muted:   "rgb(var(--c-bad-muted) / <alpha-value>)",
        },
        info: {
          DEFAULT: "rgb(var(--c-info) / <alpha-value>)",
          muted:   "rgb(var(--c-info-muted) / <alpha-value>)",
        },
        block: {
          DEFAULT: "rgb(var(--c-block) / <alpha-value>)",
          muted:   "rgb(var(--c-block-muted) / <alpha-value>)",
        },
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
