/**
 * Greet a named user. Mirror of `rust-crate::greeting::render_greeting`
 * and `sample_py.greet.render_greeting`.
 *
 * Renaming this function (or its signature) is part of the
 * cross-file-refactor e2e scenario and must propagate to the Rust
 * and Python trees in the same commit.
 */
export function greet(name: string): string {
  const trimmed = name.trim();
  const who = trimmed.length === 0 ? "friend" : trimmed;
  return `Hello, ${who}!`;
}
