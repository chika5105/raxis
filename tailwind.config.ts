import type { Config } from "tailwindcss";

const config: Config = {
  content: ["./src/**/*.{ts,tsx,mdx}"],
  darkMode: "class",
  theme: {
    extend: {
      fontFamily: {
        // Loaded via next/font in app/layout.tsx — Plus Jakarta Sans body,
        // Fraunces display serif (headlines), Source Serif 4 wordmark, IBM Plex Mono.
        sans: [
          "var(--font-sans)",
          "ui-sans-serif",
          "-apple-system",
          "BlinkMacSystemFont",
          "Segoe UI",
          "sans-serif",
        ],
        display: [
          "var(--font-display)",
          "Georgia",
          "serif",
        ],
        wordmark: [
          "var(--font-wordmark)",
          "Georgia",
          "Times New Roman",
          "serif",
        ],
        mono: [
          "var(--font-mono)",
          "ui-monospace",
          "SFMono-Regular",
          "Menlo",
          "Monaco",
          "Consolas",
          "monospace",
        ],
      },
      colors: {
        accent: {
          DEFAULT: "var(--accent)",
          soft: "var(--accent-soft)",
          strong: "var(--accent-strong)",
          50: "#ecfaff",
          100: "#cef2ff",
          200: "#a4e8ff",
          300: "#6ddaff",
          400: "#27c2f0",
          500: "#0BCCE7",
          600: "#0aa6c0",
          700: "#0a7289",
          800: "#0a5d70",
          900: "#08495a",
        },
      },
      maxWidth: {
        prose: "72ch",
      },
    },
  },
  plugins: [],
};

export default config;
