import type { Config } from "tailwindcss";

const config: Config = {
  content: ["./src/**/*.{ts,tsx,mdx}"],
  darkMode: "class",
  theme: {
    extend: {
      fontFamily: {
        sans: [
          "ui-sans-serif",
          "-apple-system",
          "BlinkMacSystemFont",
          "Inter",
          "Segoe UI",
          "Helvetica",
          "Arial",
          "sans-serif",
        ],
        mono: [
          "ui-monospace",
          "SFMono-Regular",
          "Menlo",
          "Monaco",
          "Consolas",
          "Liberation Mono",
          "Courier New",
          "monospace",
        ],
      },
      colors: {
        // CSS-variable-backed semantic palette so dark/light mode flips are
        // a single CSS variable swap, not a class-rewrite at every callsite.
        // Brand cyan (#06D7F8 → #0A7289) derived from the RAXIS logo.
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
        ink: {
          50: "#f7f7f8",
          100: "#eeeef1",
          200: "#d9dade",
          300: "#b9bbc2",
          400: "#8e9099",
          500: "#6b6e78",
          600: "#52555e",
          700: "#3f424a",
          800: "#26282d",
          900: "#16171b",
          950: "#0b0c0f",
        },
      },
      maxWidth: {
        prose: "72ch",
      },
      keyframes: {
        "fade-in-up": {
          from: { opacity: "0", transform: "translateY(8px)" },
          to: { opacity: "1", transform: "translateY(0)" },
        },
      },
      animation: {
        "fade-in-up": "fade-in-up 0.5s ease-out both",
      },
    },
  },
  plugins: [],
};

export default config;
