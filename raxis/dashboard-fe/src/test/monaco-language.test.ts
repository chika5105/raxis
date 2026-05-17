import { describe, expect, it } from "vitest";

import { detectMonacoLanguage } from "@/lib/monaco-language";

/// Regression tests for the path-suffix Monaco language map. The
/// `RepoBrowser` file-viewer + `CredentialsView` reveal pane both
/// depend on this helper to pin syntax highlighting before they
/// mount Monaco, so a regression here silently degrades the
/// operator-facing TOML / Rust / Python colouring even though
/// the editor still loads. The cases below exercise every
/// language id the helper currently emits.
describe("detectMonacoLanguage", () => {
  it.each([
    ["policy.toml", "toml"],
    ["raxis/live-e2e/examples/policy.toml", "toml"],
    ["cargo.toml", "toml"],
    ["Cargo.lock", "toml"],
    ["report.json", "json"],
    ["log.jsonl", "json"],
    ["compose.yaml", "yaml"],
    ["compose.yml", "yaml"],
    ["README.md", "markdown"],
    ["NOTES.markdown", "markdown"],
    ["src/main.rs", "rust"],
    ["app.ts", "typescript"],
    ["app.tsx", "typescript"],
    ["module.js", "javascript"],
    ["module.mjs", "javascript"],
    ["util.cjs", "javascript"],
    ["script.py", "python"],
    ["entry.sh", "shell"],
    ["page.html", "html"],
    ["style.css", "css"],
    ["query.sql", "sql"],
    ["config.xml", "xml"],
    ["Dockerfile", "dockerfile"],
    ["Makefile", "makefile"],
  ])("maps %s → %s by suffix", (path, lang) => {
    expect(detectMonacoLanguage(path)).toBe(lang);
  });

  it("falls back to plaintext for unknown shapes", () => {
    expect(detectMonacoLanguage("unknown.weirdext")).toBe("plaintext");
    expect(detectMonacoLanguage("")).toBe("plaintext");
  });

  it("uses the format_hint fallback when the path lacks an extension", () => {
    // Mirrors how `CredentialsView` calls the helper —
    // `format_hint` is the kernel-supplied free-form string
    // (e.g. `"toml-with-secrets"`) which we substring-match.
    expect(detectMonacoLanguage("credentials/anthropic-realism-e2e", "toml-with-secrets")).toBe(
      "toml",
    );
    expect(detectMonacoLanguage("credentials/raw", "json")).toBe("json");
    expect(detectMonacoLanguage("credentials/dotenv", "env-file")).toBe("shell");
  });

  it("prefers path-suffix over a contradictory format_hint", () => {
    // The path-suffix should win — operators sometimes have a
    // stale `format_hint` (e.g. a credential whose file extension
    // was changed in-place) and we'd rather follow the path the
    // operator actually clicked on.
    expect(detectMonacoLanguage("policy.toml", "json")).toBe("toml");
    expect(detectMonacoLanguage("README.md", "toml")).toBe("markdown");
  });
});
