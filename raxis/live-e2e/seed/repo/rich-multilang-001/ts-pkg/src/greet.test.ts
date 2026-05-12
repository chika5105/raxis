import { strict as assert } from "node:assert";
import { test } from "node:test";

import { greet } from "./greet.js";

test("greet renders a default for empty input", () => {
  assert.equal(greet(""), "Hello, friend!");
});

test("greet trims whitespace", () => {
  assert.equal(greet("  Ada  "), "Hello, Ada!");
});

test("greet handles a multi-word name", () => {
  assert.equal(greet("Ada Lovelace"), "Hello, Ada Lovelace!");
});
