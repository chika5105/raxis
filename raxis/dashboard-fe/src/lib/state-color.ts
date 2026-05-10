// Map kernel FSM state strings to consistent badge colors.
//
// Vocabulary mirrors `raxis-types` enum strings:
//   * Initiative: Pending / Active / Paused / Completed / Closed / Failed
//   * Task:       Pending / Activated / Running / Reviewing / Blocked /
//                 Completed / Failed
//   * Session:    Spawning / Running / Paused / Completed / Failed
//
// Anything we don't recognize falls through to a neutral
// "unknown" badge so a future state name doesn't crash the UI.

export type StateBadgeTone =
  | "ok"
  | "info"
  | "warn"
  | "bad"
  | "block"
  | "muted";

const MAP: Record<string, StateBadgeTone> = {
  // Initiative
  Pending: "muted",
  Active: "info",
  Paused: "warn",
  Completed: "ok",
  Closed: "muted",
  Failed: "bad",
  // Task
  Activated: "info",
  Running: "info",
  Reviewing: "warn",
  Blocked: "block",
  // Session
  Spawning: "muted",
};

export function stateTone(state: string | null | undefined): StateBadgeTone {
  if (!state) return "muted";
  const direct = MAP[state];
  if (direct) return direct;
  // Try a normalized match (e.g. lowercase / uppercase variants).
  const norm =
    state.charAt(0).toUpperCase() + state.slice(1).toLowerCase();
  return MAP[norm] ?? "muted";
}

const TONE_CLASSES: Record<StateBadgeTone, string> = {
  ok:    "bg-ok-muted/30   border-ok    text-ok",
  info:  "bg-info-muted/30 border-info  text-info",
  warn:  "bg-warn-muted/30 border-warn  text-warn",
  bad:   "bg-bad-muted/30  border-bad   text-bad",
  block: "bg-block-muted/30 border-block text-block",
  muted: "bg-edge/40       border-edge-strong text-ink-muted",
};

export function toneClasses(tone: StateBadgeTone): string {
  return TONE_CLASSES[tone];
}
