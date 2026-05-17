/// Lightweight path → Monaco language id mapping for the
/// dashboard's read-only file viewers (RepoBrowser, snapshot
/// blob viewer, etc.). Monaco ships built-in tokenisers for
/// every id this map returns; unknown shapes fall back to
/// `"plaintext"` so the editor still mounts without throwing.
///
/// Why a separate helper (vs. inlining in each viewer):
///   * The repo browser, credentials view, plan view, and any
///     future blob viewer all want consistent language pinning
///     so an operator scanning a `policy.toml` in the repo
///     tree and the same `policy.toml` in the credentials
///     reveal pane sees the same syntax colouring.
///   * Extending the map (e.g. adding `.lockfile` support)
///     stays a one-line edit instead of a sweep across views.
///
/// Heuristic order is `path-suffix` first, then `format-hint`
/// fallback. The path-suffix wins so an operator who renames
/// `policy.toml.bak` to `policy.toml` always gets TOML
/// colouring even if the backend's `format_hint` was stale.
export function detectMonacoLanguage(
  pathOrName: string,
  formatHint?: string,
): string {
  const path = pathOrName.toLowerCase();
  const hint = (formatHint ?? "").toLowerCase();

  // ── path-suffix wins (most specific signal) ──────────────
  if (path.endsWith(".toml")) return "toml";
  if (path.endsWith(".json") || path.endsWith(".jsonl")) return "json";
  if (path.endsWith(".yaml") || path.endsWith(".yml")) return "yaml";
  if (path.endsWith(".md") || path.endsWith(".markdown")) return "markdown";
  if (path.endsWith(".rs")) return "rust";
  if (path.endsWith(".ts") || path.endsWith(".tsx")) return "typescript";
  if (path.endsWith(".js") || path.endsWith(".jsx") || path.endsWith(".mjs") || path.endsWith(".cjs")) {
    return "javascript";
  }
  if (path.endsWith(".py")) return "python";
  if (path.endsWith(".sh") || path.endsWith(".bash") || path.endsWith(".zsh")) {
    return "shell";
  }
  if (path.endsWith(".html") || path.endsWith(".htm")) return "html";
  if (path.endsWith(".css")) return "css";
  if (path.endsWith(".sql")) return "sql";
  if (path.endsWith(".xml")) return "xml";
  if (path.endsWith(".dockerfile") || path.endsWith("/dockerfile")) {
    return "dockerfile";
  }

  // ── format-hint fallback (e.g. CredentialMetadata.format_hint) ──
  if (hint.includes("toml")) return "toml";
  if (hint.includes("json")) return "json";
  if (hint.includes("yaml") || hint.includes("yml")) return "yaml";
  if (hint.includes("markdown") || hint.includes("md")) return "markdown";
  if (hint.includes("rust")) return "rust";
  if (hint.includes("typescript")) return "typescript";
  if (hint.includes("javascript")) return "javascript";
  if (hint.includes("python")) return "python";
  if (hint.includes("shell") || hint.includes("env")) return "shell";

  // ── well-known basenames without extensions ──────────────
  if (path.endsWith("/cargo.lock") || path === "cargo.lock") return "toml";
  if (path.endsWith("/cargo.toml") || path === "cargo.toml") return "toml";
  if (path.endsWith("/dockerfile") || path === "dockerfile") return "dockerfile";
  if (path.endsWith("/makefile") || path === "makefile") return "makefile";

  return "plaintext";
}
