// Map kernel FSM state strings to consistent badge colors.
//
// Vocabulary mirrors `raxis-types` enum strings:
//   * Initiative:  Draft / ApprovedPlan / Executing / Blocked /
//                  Completed / Failed / Aborted
//   * Task:        Admitted / Running / GatesPending / Completed /
//                  Failed / Aborted / Cancelled /
//                  BlockedRecoveryPending
//   * Session:     Spawning / Running / Paused / Completed / Failed
//
// A handful of legacy / aliased names ("Pending", "Active",
// "Reviewing", …) are also mapped so older callers and human-typed
// states still produce a sensible badge. Unknown strings fall
// through to a neutral "muted" badge so a future state name does
// not crash the UI.
//
// ── Theming ────────────────────────────────────────────────────
//
// `toneClasses` returns Tailwind utility strings that bake in BOTH
// the light and dark variants for each tone (e.g. `text-emerald-800
// dark:text-emerald-200`). We deliberately avoid going through the
// global `--c-ok` / `--c-bad` semantic tokens here — at the time
// this file was last revised those tokens were tuned for dark mode
// and the resulting StateBadge contrast on the warm off-white
// light canvas landed at ~4.27 (`ok`, dark) and ~4.42 (`warn`,
// DAG legend) — i.e. either failing or skating just above WCAG AA
// 4.5:1 with no headroom.
//
// Mirroring the pattern landed by `worker/fe-audit-banner-contrast`
// (commit 9e8f063, ChainStatusBanner.tsx), each tone is now spelt
// out with explicit per-mode Tailwind palette steps. Worst-case
// contrast at the time of writing (text vs. composited tinted
// background on `--c-panel-raised`):
//
//   tone     light (badge)   dark (badge)
//   ─────    ─────────────   ────────────
//   ok       6.70:1          9.74:1   ✓ AAA
//   warn     6.20:1          10.17:1  ✓ AAA
//   bad      6.73:1          8.33:1   ✓ AAA
//   info     7.45:1          8.54:1   ✓ AAA
//   block    7.64:1          8.41:1   ✓ AAA
//   muted    8.94:1          8.82:1   ✓ AAA
//
// All values cleared with the Python helper kept in
// `dashboard-fe/QA-CHECKLIST.md` and re-run on every contrast
// audit. No global semantic-token (`--c-ok` / `--c-bad` / …) is
// touched — the rest of the dashboard chrome (cards, ink colours,
// scrollbar etc.) keeps using those tokens unchanged.

export type StateBadgeTone =
  | "ok"
  | "info"
  | "warn"
  | "bad"
  | "block"
  | "muted";

/// Canonical kernel `TaskState` SQL strings — the eight variants of
/// `raxis_types::fsm::TaskState` as encoded in the
/// `tasks.state` SQL CHECK constraint
/// (`kernel-store.md §2.5.1 Table 5`).
///
/// **`INV-DASHBOARD-TASK-STATE-COMPLETENESS-01`** — the dashboard
/// state-color map (`MAP` below) MUST carry a non-fallback entry
/// for every value in this array; the matching test in
/// `dashboard-fe/src/test/state-color.test.ts` walks the array and
/// asserts `MAP` is exhaustive. The kernel-side companion witness
/// (`crates/dashboard-kernel/src/lib.rs::inv_dashboard_task_state_completeness_*`)
/// pins the enum length so a future variant cannot land without
/// updating both sides in the same commit.
export const KERNEL_TASK_STATES = [
  "Admitted",
  "Running",
  "GatesPending",
  "Completed",
  "Failed",
  "Aborted",
  "Cancelled",
  "BlockedRecoveryPending",
] as const;

/// Canonical kernel `InitiativeState` SQL strings — the seven
/// variants of `raxis_types::fsm::InitiativeState`. Mirrors the
/// `initiatives.state` SQL CHECK constraint
/// (`kernel-store.md §2.5.1 Table 2`).
export const KERNEL_INITIATIVE_STATES = [
  "Draft",
  "ApprovedPlan",
  "Executing",
  "Blocked",
  "Completed",
  "Failed",
  "Aborted",
] as const;

/// Canonical session-row state strings the dashboard kernel-glue
/// emits via `session_row_state()` in
/// `crates/dashboard-kernel/src/lib.rs`. The session FSM in
/// `raxis_types::fsm::SessionState` carries `Spawning`/`Running`/
/// `Paused`/`Completed`/`Failed`, plus the dashboard-derived
/// terminal classifications `Revoked` and `Expired`
/// (`INV-DASHBOARD-SESSION-DETAIL-FORENSIC-01`).
export const KERNEL_SESSION_STATES = [
  "Spawning",
  "Running",
  "Paused",
  "Completed",
  "Failed",
  "Revoked",
  "Expired",
] as const;

const MAP: Record<string, StateBadgeTone> = {
  // ── InitiativeState (raxis-types::fsm::InitiativeState) ─────
  Draft: "muted",
  ApprovedPlan: "warn", // approved but not yet executing — at-rest
  Executing: "info",
  Blocked: "block",
  Completed: "ok",
  Failed: "bad",
  Aborted: "block", // terminal-but-unnatural — surfaced as "block"
  // so it visually distinguishes from the muted "queued" states

  // ── TaskState (raxis-types::fsm::TaskState) ─────────────────
  Admitted: "muted", // queued, waiting for first intent
  Running: "info",
  GatesPending: "warn", // paused awaiting gate evaluation
  Cancelled: "block", // bulk-cancelled by abort_initiative
  BlockedRecoveryPending: "warn", // crash recovery in flight
  // (Completed / Failed / Aborted shared with InitiativeState)

  // ── SessionState (raxis-types::fsm::SessionState) ───────────
  Spawning: "muted",
  Paused: "warn",
  // Terminal session classifications surfaced by the dashboard's
  // forensic-detail path (`INV-DASHBOARD-SESSION-DETAIL-FORENSIC-01`)
  // — sessions that have terminated are still navigable from the
  // list page, and the badge needs to spell out *why* the row is
  // no longer active.
  //
  //  * `Revoked` — deliberate kernel / operator revocation; gets
  //    the `block` tone (matches `Cancelled`/`Aborted` semantics:
  //    terminal-but-unnatural cause).
  //  * `Expired` — passive lapse of `expires_at`; rendered muted
  //    because it's the expected terminal state, not a failure.
  Revoked: "block",
  Expired: "muted",

  // ── Legacy / human-typed aliases ────────────────────────────
  // Older callsites (and a few test fixtures) used these names
  // before the kernel FSM converged on the canonical set above;
  // we keep mapping them so a stale string does not flash
  // "unknown" at the operator.
  Pending: "muted",
  Ready: "muted",
  Active: "info",
  Activated: "info",
  Reviewing: "warn",
  AwaitingReview: "warn",
  Closed: "muted",
  Succeeded: "ok",
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

/// Whether the dashboard's state-color map has an EXPLICIT entry
/// for this PascalCase kernel state — i.e. not via the
/// case-normalised fallback and not via the "unknown → muted"
/// trap door. Used by the exhaustiveness test for
/// `INV-DASHBOARD-TASK-STATE-COMPLETENESS-01` to assert every
/// kernel `TaskState` variant is registered as a first-class
/// renderer entry rather than silently collapsing into
/// `Admitted`-style muted styling.
///
/// We intentionally do NOT consult the normalised-fallback path
/// here: the contract is "every kernel state has a distinct
/// visual representation", which is only satisfied by a direct
/// `MAP[state]` hit. The legacy-alias bucket (Pending / Active /
/// Reviewing / …) lives behind this seam — those strings count
/// as explicit entries for their own keys but do not give cover
/// to a missing canonical `TaskState` entry.
export function hasExplicitStateEntry(state: string): boolean {
  return Object.prototype.hasOwnProperty.call(MAP, state);
}

// Each tone bakes in BOTH light and dark Tailwind palette steps.
// See the file-level comment for WCAG ratios; in short, the light
// pair uses `-700/10` tinted bg + `-700/40` border + `-800` text
// (or `-900` for warn, where amber-800 was still ~4.4:1) and the
// dark pair uses `-500/10` bg + `-500/40` border + `-200` text.
const TONE_CLASSES: Record<StateBadgeTone, string> = {
  ok:
    "border-emerald-700/40 bg-emerald-700/10 text-emerald-800 " +
    "dark:border-emerald-500/40 dark:bg-emerald-500/10 dark:text-emerald-200",
  info:
    "border-blue-700/40 bg-blue-700/10 text-blue-800 " +
    "dark:border-blue-500/40 dark:bg-blue-500/10 dark:text-blue-200",
  warn:
    "border-amber-700/40 bg-amber-700/10 text-amber-900 " +
    "dark:border-amber-500/40 dark:bg-amber-500/10 dark:text-amber-200",
  bad:
    "border-rose-700/50 bg-rose-700/10 text-rose-800 " +
    "dark:border-rose-500/50 dark:bg-rose-500/10 dark:text-rose-200",
  block:
    "border-violet-700/40 bg-violet-700/10 text-violet-800 " +
    "dark:border-violet-500/40 dark:bg-violet-500/10 dark:text-violet-200",
  muted:
    "border-neutral-400/50 bg-neutral-400/10 text-neutral-800 " +
    "dark:border-neutral-500/40 dark:bg-neutral-500/10 dark:text-neutral-200",
};

export function toneClasses(tone: StateBadgeTone): string {
  return TONE_CLASSES[tone];
}

/// Returns true when the kernel state string represents a
/// terminal failure / rejection / blocked-recovery condition —
/// i.e. an entity for which a `FailureInfo` reason SHOULD be
/// surfaced via `<FailureReasonPanel>` /  `<FailurePill>`.
///
/// Used across the dashboard to decide whether the missing-reason
/// "kernel bug" affordance should fire. Mirrors the kernel-side
/// terminal-failure classifier used when projecting
/// `FailureInfo` onto entity view shapes.
///
/// Anchors: `INV-DASHBOARD-FAILURE-VISIBILITY-01`.
export function isTerminalFailureState(
  state: string | null | undefined,
): boolean {
  if (!state) return false;
  // Match against the canonical PascalCase variants used by the
  // kernel FSMs (`raxis-types::fsm::*`). `BlockedRecoveryPending`
  // counts as a failure-bearing state because the kernel has
  // already captured a `block_reason` for it, and the operator
  // needs to see why recovery is pending.
  const FAILURE_STATES = new Set([
    "Failed",
    "Aborted",
    "Cancelled",
    "Revoked",
    "Errored",
    "BlockedRecoveryPending",
    "VmFailedFinal",
  ]);
  return FAILURE_STATES.has(state);
}

/// Compact uppercase label for tight surfaces (DAG node chips,
/// inline-list ribbons) that can't fit the full kernel state
/// name. Splits PascalCase tokens on uppercase boundaries and
/// keeps the first token, then uppercases. Examples:
///
///   Completed              → "COMPLETED"
///   Running                → "RUNNING"
///   GatesPending           → "GATES"
///   BlockedRecoveryPending → "BLOCKED"
///   AwaitingReview         → "AWAITING"
///   ApprovedPlan           → "APPROVED"
///
/// Always-readable upper-bound: 10 characters. Falls back to a
/// raw uppercase truncation if the splitter yields nothing
/// useful, so a future state name can never crash the renderer.
// ---------------------------------------------------------------------------
// IntegrationMerge synthetic-task display surface
// `INV-DASHBOARD-INTEGRATION-MERGE-VISIBLE-OR-EXCLUDED-01`
// ---------------------------------------------------------------------------
//
// The kernel inserts a synthetic "coordinator task" whose
// `task_id == initiative_id` at `approve_plan` time
// (`auto_spawn_orchestrator_session_in_tx` in
// `kernel/src/initiatives/lifecycle.rs`). The dashboard-kernel
// projection stamps a fixed human title (`Integration merge`)
// for that row; the FE then substitutes a stable display id
// (`«integration-merge»`) wherever it would otherwise render the
// initiative UUID as the task's <Mono> id chip. Routing keeps
// using the real UUID so `/tasks/<initiative_id>` continues to
// resolve and deep-links survive.

/// Stable display id rendered in place of the IntegrationMerge
/// coordinator's UUID. Spec-pinned at this exact string by
/// `INV-DASHBOARD-INTEGRATION-MERGE-VISIBLE-OR-EXCLUDED-01` so
/// operators can grep the dashboard for the string and reach
/// the merge task immediately.
export const INTEGRATION_MERGE_DISPLAY_ID = "«integration-merge»";

/// True when this `task_id` denotes the synthetic IntegrationMerge
/// coordinator row for the supplied initiative. The kernel
/// admits the row with `task_id == initiative_id` by construction
/// (`v2-deep-spec.md §Step 11 IntegrationMerge`); sub-task ids
/// are operator-authored strings and live in a disjoint space.
export function isIntegrationMergeTask(
  taskId: string | null | undefined,
  initiativeId: string | null | undefined,
): boolean {
  if (!taskId || !initiativeId) return false;
  return taskId === initiativeId;
}

/// What the dashboard renders inside the per-initiative task
/// list's `<Mono>` task-id chip. Returns the stable
/// `«integration-merge»` display id for the synthetic
/// coordinator row and the verbatim `task_id` otherwise. The
/// wire `task_id` is unchanged — this helper is render-time
/// only.
export function taskDisplayId(
  taskId: string,
  initiativeId: string | null | undefined,
): string {
  return isIntegrationMergeTask(taskId, initiativeId)
    ? INTEGRATION_MERGE_DISPLAY_ID
    : taskId;
}

export function shortStateLabel(state: string | null | undefined): string {
  if (!state) return "—";
  const trimmed = state.trim();
  if (trimmed.length === 0) return "—";
  // Match the leading PascalCase token: an uppercase letter
  // followed by lowercase/digit characters until the next
  // uppercase boundary or end-of-string.
  const head = trimmed.match(/^[A-Z][a-z0-9]*/);
  const candidate = head ? head[0] : trimmed;
  const upper = candidate.toUpperCase();
  return upper.length <= 10 ? upper : `${upper.slice(0, 9)}…`;
}
