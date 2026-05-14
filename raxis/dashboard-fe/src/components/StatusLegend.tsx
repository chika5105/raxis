import clsx from "clsx";

import {
  stateDescription,
  stateGlyph,
  stateTone,
  toneClasses,
  type StateBadgeTone,
} from "@/lib/state-color";

interface StatusLegendProps {
  /// Per-state counts as a plain object — `{ Running: 3, Completed: 7 }`.
  /// Iteration follows insertion order so callers can sort upstream
  /// (kernel-canonical, alphabetical, severity, etc.) and the legend
  /// renders chips in that order.
  counts: Record<string, number>;
  /// Currently-active filter set, in URL order. Empty array means
  /// "no filter" — every chip renders inactive.
  activeStatuses: string[];
  /// Click handler — `multiSelect` is true when the operator held
  /// Cmd (macOS) or Ctrl (Windows/Linux). The callee decides what
  /// "toggle" means; see `toggleStatus()` in `lib/status-filter.ts`
  /// for the canonical implementation that every page uses.
  onToggle: (status: string, multiSelect: boolean) => void;
  /// Optional explicit clear handler. When omitted, the "Clear"
  /// affordance simply emits `onToggle(state, false)` for each
  /// active status to drop them, but a callee usually wants to do
  /// a single URL edit instead — provide `onClear` to short-circuit
  /// that round-trip.
  onClear?: () => void;
  /// Singular noun for the items being counted, e.g. `"task"` or
  /// `"session"`. Surfaced in tooltips ("Filter to Running tasks")
  /// and screen-reader labels so the legend is unambiguous on
  /// pages that mix multiple list types (Sessions vs Tasks vs
  /// Initiatives).
  itemNoun?: string;
  /// Optional className passthrough.
  className?: string;
}

/// Click-to-filter status legend. Renders one chip per status with
/// `{state} · {count}`, hover affordance, active-state ring, and
/// keyboard-friendly toggling. Cmd/Ctrl-click adds to a multi-
/// select set instead of replacing it.
///
/// Visual contract:
///   * Chips look like a regular `<StateBadge>` but with a
///     `cursor-pointer` + brightness bump on hover so they look
///     clickable.
///   * Active chips get a tone-coloured 2-px ring and a bolder
///     count number so the selection reads at a glance.
///   * `count === 0` chips dim to `opacity-60` — they remain a
///     color-key reference but signal "nothing here right now".
///
/// Keyboard contract:
///   * Each chip is a `<button>`; Tab moves between them and
///     Enter / Space toggles. Cmd-/Ctrl-Enter performs a multi-
///     select toggle, mirroring the mouse behaviour.
export function StatusLegend({
  counts,
  activeStatuses,
  onToggle,
  onClear,
  itemNoun = "item",
  className,
}: StatusLegendProps) {
  const activeSet = new Set(activeStatuses);
  const hasActive = activeStatuses.length > 0;
  const handleClear = () => {
    if (onClear) onClear();
    else activeStatuses.forEach((s) => onToggle(s, false));
  };
  const entries = Object.entries(counts);

  return (
    <div
      className={clsx("flex flex-wrap items-center gap-1.5", className)}
      role="group"
      aria-label="Status filter"
    >
      {entries.map(([status, count]) => {
        const tone = stateTone(status);
        const glyph = stateGlyph(status);
        const description = stateDescription(status);
        const active = activeSet.has(status);
        const dim = count === 0 && !active;
        const itemPlural = count === 1 ? itemNoun : `${itemNoun}s`;
        // `INV-DASHBOARD-FSM-STATE-VISIBILITY-01` — the legend
        // chip carries the same `(tone-coloured pill) + (glyph) +
        // (label) + (count)` composition as `<StateBadge>` so the
        // legend doubles as the per-state colour-key reference. The
        // chip's `title=` text expands to the full operator-facing
        // description (e.g. "Aborted: operator-initiated stop via
        // `abort_initiative`") rather than the bare label so a new
        // operator does not have to leave the page to learn what the
        // states mean.
        const baseTitle = active
          ? `Clear ${status} filter (Cmd-click to keep others)`
          : `Filter to ${status} ${itemPlural}${
              count > 0 ? ` (${count})` : ""
            } — Cmd-click for multi-select`;
        const titleText = description
          ? `${baseTitle}\n\n${status}: ${description}`
          : baseTitle;
        return (
          <button
            key={status}
            type="button"
            onClick={(e) => onToggle(status, e.metaKey || e.ctrlKey)}
            onKeyDown={(e) => {
              if (
                (e.key === "Enter" || e.key === " ") &&
                (e.metaKey || e.ctrlKey)
              ) {
                e.preventDefault();
                onToggle(status, true);
              }
            }}
            aria-pressed={active}
            title={titleText}
            className={clsx(
              "badge cursor-pointer select-none transition-all",
              toneClasses(tone),
              "hover:brightness-110 hover:saturate-150",
              "focus:outline-none focus-visible:ring-2 focus-visible:ring-accent focus-visible:ring-offset-1 focus-visible:ring-offset-panel",
              active &&
                "ring-2 ring-offset-1 ring-offset-panel font-semibold " +
                  ringToneClass(tone),
              dim && "opacity-60",
            )}
          >
            <span
              aria-hidden="true"
              className={clsx(
                "mr-1.5 inline-block h-1.5 w-1.5 rounded-full",
                dotToneClass(tone),
              )}
            />
            <span aria-hidden="true" className="mr-1 font-mono text-[0.95em] leading-none">
              {glyph}
            </span>
            <span>{status}</span>
            <span className="ml-1.5 tabular text-[11px] opacity-80">
              {count}
            </span>
          </button>
        );
      })}

      {hasActive && (
        <button
          type="button"
          onClick={handleClear}
          className="text-[11px] text-accent hover:underline ml-1"
          title="Clear all status filters"
        >
          Clear
        </button>
      )}
    </div>
  );
}

interface StatusFilterPillsProps {
  /// Currently-active filter set, in URL order. Renders one pill
  /// per state, each with an × button to drop just that filter.
  /// Hidden when empty — the pills row is purely a "what's active
  /// right now" indicator and adds noise when nothing is filtered.
  activeStatuses: string[];
  /// Drop a single status from the filter set.
  onRemove: (status: string) => void;
  /// Drop the entire filter set in a single URL edit.
  onClearAll: () => void;
  /// Optional className passthrough.
  className?: string;
}

/// Pills row above a list showing the active filter set, with × on
/// each pill to drop that filter and a "clear all" affordance. Used
/// alongside `<StatusLegend>` on every page where the click-to-
/// filter pattern is wired (Initiatives detail, DAG, Sessions, etc.)
/// so the operator always has a visible undo path even after
/// scrolling past the legend.
export function StatusFilterPills({
  activeStatuses,
  onRemove,
  onClearAll,
  className,
}: StatusFilterPillsProps) {
  if (activeStatuses.length === 0) return null;
  return (
    <div
      className={clsx(
        "flex flex-wrap items-center gap-1.5 text-xs",
        className,
      )}
      role="status"
      aria-live="polite"
    >
      <span className="text-ink-subtle">Active filter:</span>
      {activeStatuses.map((s) => {
        const tone = stateTone(s);
        const glyph = stateGlyph(s);
        return (
          <span
            key={s}
            className={clsx(
              "badge",
              toneClasses(tone),
              "ring-1 ring-offset-1 ring-offset-panel",
              ringToneClass(tone),
            )}
          >
            <span
              aria-hidden="true"
              className={clsx(
                "mr-1.5 inline-block h-1.5 w-1.5 rounded-full",
                dotToneClass(tone),
              )}
            />
            <span aria-hidden="true" className="mr-1 font-mono text-[0.95em] leading-none">
              {glyph}
            </span>
            {s}
            <button
              type="button"
              onClick={() => onRemove(s)}
              className="ml-1.5 -mr-0.5 inline-flex items-center justify-center w-3.5 h-3.5 rounded-full text-current opacity-70 hover:opacity-100 hover:bg-current/10"
              aria-label={`Remove ${s} filter`}
              title={`Remove ${s} filter`}
            >
              ×
            </button>
          </span>
        );
      })}
      <button
        type="button"
        onClick={onClearAll}
        className="text-accent hover:underline ml-1"
      >
        clear all
      </button>
    </div>
  );
}

/// Tailwind ring-color utility for each tone. Kept off the main
/// `toneClasses` map because rings are only used by interactive
/// surfaces (the StatusLegend chips and StatusFilterPills) — the
/// badge tone itself does not own a ring color.
function ringToneClass(tone: StateBadgeTone): string {
  switch (tone) {
    case "ok":
      return "ring-ok";
    case "info":
      return "ring-info";
    case "warn":
      return "ring-warn";
    case "bad":
      return "ring-bad";
    case "block":
      return "ring-block";
    case "muted":
      return "ring-edge-strong";
  }
}

/// Solid colour dot used as a discriminating mark on each chip — at
/// small sizes the tinted background alone doesn't read as a state
/// difference, but a 6 px solid dot in the tone color does, and it
/// reinforces the StateBadge color-coding without re-rendering the
/// whole badge.
function dotToneClass(tone: StateBadgeTone): string {
  switch (tone) {
    case "ok":
      return "bg-ok";
    case "info":
      return "bg-info";
    case "warn":
      return "bg-warn";
    case "bad":
      return "bg-bad";
    case "block":
      return "bg-block";
    case "muted":
      return "bg-ink-subtle";
  }
}
