"use strict";

module.exports = [
  {
    files: ["src/**/*.ts"],
    languageOptions: {
      ecmaVersion: 2022,
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
