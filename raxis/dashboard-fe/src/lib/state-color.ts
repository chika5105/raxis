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
// Mirroring the pattern landed in `ChainStatusBanner.tsx`,
// each tone is now spelt
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

/// Per-state visual treatment — one row per kernel FSM variant.
///
/// `INV-DASHBOARD-FSM-STATE-VISIBILITY-01` — every kernel
/// `TaskState` / `InitiativeState` / dashboard session-row state
/// MUST resolve to a `(tone, glyph, label, description)` tuple
/// here, and the `(tone, glyph)` pair MUST be unique within each
/// enum so an operator can tell two states apart at a glance even
/// when colour collapses on a colour-blindness filter or a tinted
/// monitor. Colour alone is insufficient (Aborted vs Cancelled
/// both naturally land on `block`; GatesPending vs ApprovedPlan
/// both naturally land on `warn`); the glyph is the
/// disambiguator. The witness in
/// `dashboard-fe/src/test/state-color.test.ts` walks every
/// `KERNEL_*_STATES` array and asserts the glyph + label + tone
/// triple is unique within the enum.
///
/// **Glyph vocabulary** — all glyphs are single-codepoint
/// monospace-friendly Unicode chosen to render on stock system
/// fonts WITHOUT requiring an icon font dependency. The
/// `pulse` flag turns on the `pulse-dot` animation in
/// `StateBadge.tsx` for the few "actively in motion" states (any
/// `Running`-class state plus `Executing`).
export interface StateVisualTreatment {
  tone:        StateBadgeTone;
  /// Single-codepoint glyph rendered before the label in
  /// `<StateBadge>` and `<StatusLegend>`. Non-empty by contract.
  glyph:       string;
  /// Human-readable label. Exposed for tooltips and the
  /// status-legend chip; usually mirrors the wire string but
  /// CAN differ for legacy aliases.
  label:       string;
  /// One-line description shown on hover / in the legend's
  /// expanded pop-out — the canonical operator-facing meaning of
  /// this state. Helps a new operator distinguish e.g. Aborted
  /// (operator-driven stop) from Cancelled (kernel-driven
  /// abort cascade).
  description: string;
  /// Whether the badge should show a pulsing dot. Reserved for
  /// the few "actively executing" states where the pulse mirrors
  /// the absence of a steady-state.
  pulse?:      boolean;
}

const VISUAL: Record<string, StateVisualTreatment> = {
  // ── InitiativeState (raxis-types::fsm::InitiativeState) ─────
  Draft: {
    tone: "muted", glyph: "◇", label: "Draft",
    description: "plan not yet approved by an operator",
  },
  ApprovedPlan: {
    tone: "warn", glyph: "◆", label: "ApprovedPlan",
    description: "operator approved the plan; orchestrator not yet spawned",
  },
  Executing: {
    tone: "info", glyph: "▶", label: "Executing", pulse: true,
    description: "orchestrator is driving sub-tasks toward terminality",
  },
  Blocked: {
    tone: "block", glyph: "⏸", label: "Blocked",
    description: "no admissible task; operator unblock or escalation required",
  },
  Completed: {
    tone: "ok", glyph: "✓", label: "Completed",
    description: "terminal success — every required task reached Completed",
  },
  Failed: {
    tone: "bad", glyph: "✗", label: "Failed",
    description: "terminal failure — a required task or merge step failed",
  },
  Aborted: {
    tone: "block", glyph: "⊠", label: "Aborted",
    description: "operator-initiated stop via `abort_initiative`",
  },

  // ── TaskState (raxis-types::fsm::TaskState) ─────────────────
  // Admitted vs Running used to be visually identical at a glance
  // (Admitted=muted, Running=info+pulse). The pulse helped, but
  // when the dashboard never received a push for the
  // Admitted → Running edge (iter56 root cause) the operator's
  // only fallback was reading two near-identical badge labels.
  // The glyph column makes the two trivially distinguishable in
  // every surface (badge, DAG node chip, legend).
  Admitted: {
    tone: "muted", glyph: "◌", label: "Admitted",
    description: "queued; awaiting first planner intent or session spawn",
  },
  Running: {
    tone: "info", glyph: "▶", label: "Running", pulse: true,
    description: "an executor is actively processing intents on this task",
  },
  GatesPending: {
    tone: "warn", glyph: "⏳", label: "GatesPending",
    description: "paused awaiting witness records for one or more gates",
  },
  Cancelled: {
    tone: "block", glyph: "⊘", label: "Cancelled",
    description: "kernel-initiated cancel via `abort_initiative` cascade",
  },
  BlockedRecoveryPending: {
    tone: "warn", glyph: "↻", label: "BlockedRecoveryPending",
    description: "in-flight at kernel crash; awaits operator `task resume`",
  },
  // (TaskState reuses Completed / Failed / Aborted entries above;
  //  they keep the same (tone, glyph, label) triple deliberately
  //  — the same wire string MUST mean the same thing across enums.)

  // ── SessionState (raxis-types::fsm::SessionState + dashboard-derived) ─
  Spawning: {
    tone: "muted", glyph: "◌", label: "Spawning",
    description: "VM substrate is booting; planner has not connected yet",
  },
  Paused: {
    tone: "warn", glyph: "⏸", label: "Paused",
    description: "session blocked on an outstanding kernel push (e.g. escalation)",
  },
  Revoked: {
    tone: "block", glyph: "⊠", label: "Revoked",
    description: "kernel/operator revoked this session token; planner cannot resume",
  },
  Expired: {
    tone: "muted", glyph: "…", label: "Expired",
    description: "passive lapse of `expires_at`; expected terminal lifecycle end",
  },

  // ── Legacy / human-typed aliases ────────────────────────────
  // Older callsites (and a few test fixtures) used these names
  // before the kernel FSM converged on the canonical set above;
  // we keep mapping them so a stale string does not flash
  // "unknown" at the operator.
  Pending:        { tone: "muted", glyph: "◌", label: "Pending",        description: "legacy alias for queued" },
  Ready:          { tone: "muted", glyph: "◌", label: "Ready",          description: "legacy alias for ready-to-pickup" },
  Active:         { tone: "info",  glyph: "▶", label: "Active", pulse: true,
                    description: "legacy alias for Running" },
  Activated:      { tone: "info",  glyph: "▶", label: "Activated", pulse: true,
                    description: "legacy alias for Running" },
  Reviewing:      { tone: "warn",  glyph: "⏳", label: "Reviewing",      description: "legacy alias for in-review" },
  AwaitingReview: { tone: "warn",  glyph: "⏳", label: "AwaitingReview", description: "legacy alias for AwaitingReview" },
  Closed:         { tone: "muted", glyph: "…", label: "Closed",         description: "legacy alias for terminal close" },
  Succeeded:      { tone: "ok",    glyph: "✓", label: "Succeeded",      description: "legacy alias for Completed" },
};

const MAP: Record<string, StateBadgeTone> = Object.fromEntries(
  Object.entries(VISUAL).map(([state, treatment]) => [state, treatment.tone]),
);

/// Lookup the per-state visual treatment. Returns `null` when the
/// state is not registered — callers should fall through to the
/// muted default. Case-normalises like [`stateTone`] so a
/// lower-cased planner-emitted state still resolves.
export function stateVisualTreatment(
  state: string | null | undefined,
): StateVisualTreatment | null {
  if (!state) return null;
  const direct = VISUAL[state];
  if (direct) return direct;
  const norm = state.charAt(0).toUpperCase() + state.slice(1).toLowerCase();
  return VISUAL[norm] ?? null;
}

/// Single-codepoint glyph for the badge. Falls back to `•` for
/// unknown states so the badge renders predictably.
export function stateGlyph(state: string | null | undefined): string {
  return stateVisualTreatment(state)?.glyph ?? "•";
}

/// Human-friendly state description (one line, surfaces on hover
/// in `<StateBadge>` via `title=`).
export function stateDescription(
  state: string | null | undefined,
): string {
  return stateVisualTreatment(state)?.description ?? "";
}

/// Whether `<StateBadge>` should render the pulsing dot for this
/// state. Pre-fix the pulse was conditional only on `tone === "info"`,
/// which collapsed every active session/initiative under the same
/// rule. The treatment table now drives this explicitly so e.g.
/// `Executing` (initiative) and `Running` (task) both pulse but
/// `Active` (legacy session alias) can opt in too.
export function stateShouldPulse(state: string | null | undefined): boolean {
  return Boolean(stateVisualTreatment(state)?.pulse);
}

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
