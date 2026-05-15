// Flat ESLint config for the Vite 6 + React 18 dashboard frontend.
//
// Stack:
//   - eslint 9 (flat config)
//   - typescript-eslint (unified package)
//   - eslint-plugin-react / react-hooks / react-refresh
//
// We deliberately use the non-type-checked `tseslint.configs.recommended`
// preset rather than `recommendedTypeChecked`. Type-checked rules require
// `parserOptions.project`, which would walk the full TS program on every
// `eslint .` invocation and roughly double lint time on this project; the
// existing `npm run typecheck` already enforces full type safety.
import js from "@eslint/js";
import reactPlugin from "eslint-plugin-react";
import reactHooks from "eslint-plugin-react-hooks";
import reactRefresh from "eslint-plugin-react-refresh";
import globals from "globals";
import tseslint from "typescript-eslint";

export default tseslint.config(
  {
    ignores: [
      "dist/**",
      "node_modules/**",
      "vendor/**",
      "coverage/**",
      "**/*.d.ts",
    ],
  },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ["**/*.{ts,tsx}"],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: "module",
      globals: {
        ...globals.browser,
        ...globals.es2022,
      },
      parserOptions: {
        ecmaFeatures: { jsx: true },
      },
    },
    settings: {
      react: { version: "detect" },
    },
    plugins: {
      react: reactPlugin,
      "react-hooks": reactHooks,
      "react-refresh": reactRefresh,
    },
    rules: {
      ...reactPlugin.configs.recommended.rules,
      ...reactPlugin.configs["jsx-runtime"].rules,
      ...reactHooks.configs.recommended.rules,
      "react-refresh/only-export-components": [
        "warn",
        { allowConstantExport: true },
      ],
      // React 18 + the new JSX transform: `React` does not need to be in
      // scope, and `prop-types` is not used in a TypeScript project.
      "react/react-in-jsx-scope": "off",
      "react/prop-types": "off",
    },
  },
  {
    // Node-context configs (Vite, Tailwind, PostCSS, etc.) live at the repo
    // root. They are CommonJS or ESM modules executed by Node, not browser
    // bundles, so we widen the globals accordingly.
    files: [
      "vite.config.ts",
      "vitest.config.ts",
      "tailwind.config.{js,ts}",
      "postcss.config.{js,cjs}",
    ],
    languageOptions: {
      globals: { ...globals.node },
    },
  },
  {
    // Test files: pull in jest-dom / vitest globals so common matchers and
    // `describe`/`it`/`expect` don't trip `no-undef` even though we don't
    // declare them globally in `vitest.config.ts`.
    files: ["src/test/**/*.{ts,tsx}", "**/*.{test,spec}.{ts,tsx}"],
    languageOptions: {
      globals: {
        ...globals.node,
        ...globals.jest,
      },
    },
  },
);
