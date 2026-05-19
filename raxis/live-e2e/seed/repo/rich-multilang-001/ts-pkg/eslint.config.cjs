"use strict";

const { createRequire } = require("node:module");

function requireGlobal(pkg) {
  for (const root of ["/usr/lib/node_modules/", "/usr/local/lib/node_modules/"]) {
    try {
      return createRequire(`${root}.raxis-global-require.cjs`)(pkg);
    } catch (error) {
      if (error && error.code !== "MODULE_NOT_FOUND") {
        throw error;
      }
    }
  }
  return require(pkg);
}

const tsParser = requireGlobal("@typescript-eslint/parser");

module.exports = [
  {
    files: ["src/**/*.ts"],
    languageOptions: {
      ecmaVersion: 2022,
      parser: tsParser,
      sourceType: "module",
    },
    rules: {
      "no-unused-vars":      ["error", { argsIgnorePattern: "^_" }],
      "no-console":          ["warn"],
      "no-var":              ["error"],
      "prefer-const":        ["error"],
      "eqeqeq":              ["error", "always"],
      "curly":               ["error", "all"],
      "no-trailing-spaces":  ["error"],
    },
  },
];
