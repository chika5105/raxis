/// URL ↔ status-filter helpers for the click-to-filter status
/// legend. Kept as pure functions (no React deps) so they're trivial
/// to unit-test and so each consuming page can apply its own URL-
/// search-params plumbing while preserving any other concurrent
/// query params (e.g. `?initiative_id=` from the Sessions page).
///
/// Wire format: `?status=Running,Completed`. The serialised value
/// is a comma-separated list of kernel state strings; parsing is
/// strict-trim, drops empties, and de-duplicates while preserving
/// first-seen order. Invalid characters (anything that survives
/// `URLSearchParams` decoding) are passed through verbatim — pages
/// that want to restrict to a known taxonomy can intersect against
/// their per-page state vocabulary after parsing.

/// Parse the wire `?status=` value into an array of state strings.
///
///   parseStatusParam(null)              → []
///   parseStatusParam("")                → []
///   parseStatusParam("Running")         → ["Running"]
///   parseStatusParam("Running,Failed")  → ["Running", "Failed"]
///   parseStatusParam(" A , , B ,A ")    → ["A", "B"]   (trim + dedupe)
export function parseStatusParam(raw: string | null | undefined): string[] {
  if (!raw) return [];
  const seen = new Set<string>();
  const out: string[] = [];
  for (const part of raw.split(",")) {
    const trimmed = part.trim();
    if (!trimmed || seen.has(trimmed)) continue;
    seen.add(trimmed);
    out.push(trimmed);
  }
  return out;
}

/// Serialise the active set back to a comma-separated wire string.
/// Empty input → `""`, which callers should `delete` from the
/// `URLSearchParams` (rather than emitting `?status=`) so the URL
/// reads cleanly when the filter is cleared.
export function serializeStatusParam(active: readonly string[]): string {
  return active.join(",");
}

/// Apply a click toggle to the current filter set.
///
///   * `multiSelect=false` (plain click):
///       - empty            → activate this one.
///       - only this active → clear (chip toggles off).
///       - anything else    → replace with this single state.
///   * `multiSelect=true`  (Cmd/Ctrl-click):
///       - present → drop.
///       - absent  → append (insertion order preserved).
///
/// Order matters because both `<StatusLegend>` and
/// `<StatusFilterPills>` render chips in URL order — preserving
/// insertion order keeps the UI stable as the operator clicks.
export function toggleStatus(
  active: readonly string[],
  state: string,
  multiSelect: boolean,
): string[] {
  const present = active.includes(state);
  if (multiSelect) {
    if (present) return active.filter((s) => s !== state);
    return [...active, state];
  }
  if (present && active.length === 1) return [];
  return [state];
}
