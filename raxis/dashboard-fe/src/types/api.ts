// Typed mirrors of the Rust `raxis-dashboard` JSON wire shapes.
//
// Source of truth: `raxis/crates/dashboard/src/data.rs` and the
// per-route handlers under `raxis/crates/dashboard/src/routes/`.
// When the backend struct gains a field, MIRROR IT HERE — the
// FE has no fallback path; missing fields surface as runtime
// errors in the UI rather than silent drift.

export interface ApiErrorBody {
  code: string;
  message: string;
}

export interface ChallengeResponse {
  challenge: string;
  expires_at: number;
}

export interface VerifyRequest {
  challenge: string;
  signature: string;
  public_key: string;
}

export interface VerifyResponse {
  token: string;
  operator_id: string;
  display_name: string;
  roles: string[];
  expires_at: number;
}

export interface LogoutRequest {
  token: string;
}

export interface InitiativeListEntry {
  initiative_id: string;
  display_name: string;
  state: string;
  task_count: number;
  completed_tasks: number;
  failed_tasks: number;
  created_at: number;
  updated_at: number;
}

// Structured failure reason attached to a Failed / Revoked / Rejected
// entity (session, task, initiative, subsystem). Mirrors
// `raxis_dashboard::data::FailureInfo` byte-for-byte; see
// `INV-DASHBOARD-FAILURE-VISIBILITY-01`.
//
// Operator-experience contract: every red Failure pill in the UI
// MUST be backed by one of these. When the wire ships
// `failure: null` on a Failed-state entity the FE renders
// "No reason supplied — kernel bug" so the gap is visible rather
// than swallowed.
//
// `fields` is rendered as a definition list and `artifacts` as
// click-through links (kernel.stderr.log, worktree path, audit-chain
// row, …). `event_id` / `seq` anchor the reason back to the
// audit-chain row so the operator can deep-link from the panel
// to the originating event.
export interface FailureField {
  label: string;
  value: string;
}

export interface FailureArtifact {
  label: string;
  href: string;
}

export interface FailureInfo {
  /// PascalCase error class, e.g. `SessionVmFailedFinal`,
  /// `WorktreeProvisionFailed`, `ReviewerRejected`. Used as the
  /// panel headline + the `data-failure-kind` attribute for E2E
  /// selectors.
  kind: string;
  /// Free-form human-readable reason from the originating kernel
  /// event (`final_reason`, `reason`, etc.). NOT truncated /
  /// sanitised — the operator needs the raw text.
  message: string;
  /// Structured fields (`exit_code`, `target_host`, `port`, …)
  /// rendered as a `<dl>`. Empty array ⇒ no detail block.
  fields?: FailureField[];
  /// Click-through links (`kernel.stderr.log`, worktree path,
  /// audit-chain deep link, …). Empty array ⇒ no artifact block.
  artifacts?: FailureArtifact[];
  /// Audit-chain anchor (event_id + seq) so the FE can deep-link
  /// to the originating row. `null` when the reason was synthesised
  /// outside the audit chain (rare).
  event_id?: string | null;
  seq?: number | null;
  /// Unix-seconds when the failure was observed (kernel-side).
  /// Zero when unknown — the panel suppresses the timestamp row.
  observed_at?: number;
}

export interface ReviewerVerdictView {
  verdict: string;
  critique: string;
  reviewer_session_id: string;
  at: number;
}

export interface StructuredOutputView {
  kind: string;
  payload: unknown;
  at: number;
}

export interface TaskView {
  task_id: string;
  initiative_id: string;
  title: string;
  state: string;
  session_id: string | null;
  reviewer_verdicts: ReviewerVerdictView[];
  structured_outputs: StructuredOutputView[];
  path_allowlist: string[];
  created_at: number;
  updated_at: number;
  /// Failure reason, set when the task is in a terminal-failure
  /// state (`Failed`, `Revoked`, `BlockedForRecovery`, …). The
  /// dashboard renders this through `<FailureReasonPanel>` on the
  /// task detail + initiative-DAG side panel. `null` (the JSON
  /// default) ⇒ no failure reported.
  failure?: FailureInfo | null;
  /// Downstream task_ids that were blocked by this task's failure.
  /// Populated only for terminal-failure tasks so the FE can show
  /// the cascade in the DAG side panel.
  blocked_downstream?: string[];
}

export interface DagEdge {
  from: string;
  to: string;
}

export interface InitiativeView extends InitiativeListEntry {
  approved_by: string | null;
  plan_sha256: string | null;
  target_ref: string | null;
  policy_epoch: number;
  tasks: TaskView[];
  edges: DagEdge[];
  /// Failure reason, set when the initiative is in a
  /// terminal-failure state (`Failed`, `Aborted`). The dashboard
  /// renders this in `<FailureReasonPanel>` at the top of the
  /// initiative detail page.
  failure?: FailureInfo | null;
}

export interface DagNode {
  task_id: string;
  title: string;
  state: string;
}

export interface DagView {
  initiative_id: string;
  nodes: DagNode[];
  edges: DagEdge[];
}

export interface SessionView {
  session_id: string;
  role: string;
  initiative_id: string | null;
  task_id: string | null;
  state: string;
  provider: string | null;
  model: string | null;
  input_tokens: number;
  output_tokens: number;
  created_at: number;
  updated_at: number;
  /// Failure reason, set when the session is in a terminal-failure
  /// state (`Failed`, `VmFailedFinal`, `Errored`, …). The dashboard
  /// renders this through `<FailureReasonPanel>` on Sessions list +
  /// SessionDetail header.
  failure?: FailureInfo | null;
}

export interface EscalationView {
  escalation_id: string;
  initiative_id: string;
  task_id: string | null;
  severity: string;
  reason: string;
  action_required: string;
  created_at: number;
}

export interface AuditEntryView {
  seq: number;
  event_id: string;
  event_kind: string;
  initiative_id: string | null;
  task_id: string | null;
  session_id: string | null;
  at: number;
  payload: unknown;
}

// Status banner / per-row icons for the audit chain view.
//
// `status` mirrors the kernel's own verdict from
// `raxis_audit_tools::verify_chain_from`. The dashboard MUST NOT
// reimplement verification — see `INV-AUDIT-DASHBOARD-01`.
//
//   * "ok"      — every link verified end-to-end.
//   * "broken"  — at least one chain break / seq gap; UI MUST
//                 render this as a hard-red banner with the
//                 reason from `last_error`.
//   * "unknown" — verification has not run yet (boot window or
//                 audit directory absent); UI renders soft warn.
export interface ChainStatusView {
  status: "ok" | "broken" | "unknown";
  last_verified_seq: number;
  total_records: number;
  segment_count: number;
  verified_at_ms: number;
  last_error: string | null;
}

// Response envelope from `GET /api/audit/chain-status`. Flattens
// `ChainStatusView` onto the same level as `fresh`.
export interface ChainStatusResponse extends ChainStatusView {
  fresh: boolean;
}

// `GET /api/health/subsystems` — per-subsystem health cards
// for the dashboard Health tab. One card per kernel subsystem
// the dashboard enumerates (see kernel-side `SUBSYSTEM_CATALOG`).
// Verdicts come from the kernel's own bookkeeping — the FE
// never invents a status (`INV-DASHBOARD-VALIDATE-01`).
export type SubsystemHealthStatus =
  | "ok"
  | "degraded"
  | "failing"
  | "unknown";

export interface SubsystemDetailRow {
  label: string;
  value: string;
}

export interface SubsystemHealthCard {
  id: string;
  label: string;
  status: SubsystemHealthStatus;
  summary: string;
  details: SubsystemDetailRow[];
  grafana_url: string | null;
  last_observed_at: number;
  /// Most-recent failure reason for `failing` / `degraded` cards.
  /// Surfaced inline beneath the status pill so the operator
  /// never has to grep kernel.stderr.log to find out why a
  /// reporter is unhappy. `null` ⇒ healthy reporter or kernel
  /// did not supply a reason (operator-actionable bug — the
  /// card renders "No reason supplied — kernel bug" in that
  /// case).
  last_error?: string | null;
}

export interface SubsystemHealthResponse {
  aggregate_status: SubsystemHealthStatus;
  cards: SubsystemHealthCard[];
  generated_at_ms: number;
}

/**
 * `INV-NOTIF-SCOPE-01` priority bucket projected onto the row
 * server-side via
 * `raxis_dashboard_kernel::notification_priority_for_kind_str`.
 *
 * The canonical taxonomy (which `AuditEventKind`s map to which
 * priority) lives in
 * `crates/dashboard-kernel/src/notification_filter.rs`. The
 * frontend treats this string as opaque — DO NOT add new buckets
 * here without first extending the Rust enum and updating both
 * `notification_priority` arms.
 */
export type NotificationPriority = "Critical" | "High" | "Medium" | "Low";

export interface NotificationView {
  notification_id: string;
  event_kind: string;
  initiative_id: string | null;
  task_id: string | null;
  session_id: string | null;
  summary: string;
  payload: unknown;
  read: boolean;
  source_event_id: string;
  created_at: number;
  /**
   * `null` / `undefined` means the row pre-dates the
   * `notification_priority` filter (legacy data). The UI renders
   * those as an "unclassified" Low-tier fallback rather than
   * dropping them.
   */
  priority?: NotificationPriority | null;
}

export interface UnreadCountResponse {
  count: number;
}

export interface MarkReadResponse {
  updated: boolean;
}

export interface MarkAllReadResponse {
  count: number;
}

export interface PolicyOperatorView {
  fingerprint: string;
  display_name: string;
  permitted_ops: string[];
}

export interface PolicySnapshotView {
  epoch: number;
  policy_sha256: string;
  signed_by: string;
  signed_at: number;
  operators: PolicyOperatorView[];
  notification_routes: Record<string, string[]>;
}

export interface PolicyAdvancement {
  previous_epoch: number;
  new_epoch: number;
  policy_sha256: string;
  signed_by_authority: string;
  n_sessions_invalidated: number;
  n_delegations_marked_stale: number;
  advanced_at: number;
}

export interface UpdatePolicyRequest {
  toml: string;
  signature_b64: string;
}

export interface UpdatePolicyResponse {
  advancement: PolicyAdvancement;
}

export interface HealthCheck {
  id: string;
  status: string;
  message: string;
}

export interface HealthSnapshot {
  status: string;
  checks: HealthCheck[];
  kernel_booted_at: number;
  policy_epoch: number;
  active_initiatives: number;
  active_sessions: number;
  pending_escalations: number;
}

export interface WorktreeListEntry {
  name: string;
  label: string;
  kind: string;
  path: string;
  session_id: string | null;
  task_id: string | null;
  base_sha: string | null;
}

export interface WorktreeDetail extends WorktreeListEntry {
  head_sha: string | null;
  branch: string | null;
  ahead: number | null;
  behind: number | null;
  status_lines: string[];
}

export interface WorktreeLogEntry {
  sha: string;
  short_sha: string;
  author: string;
  subject: string;
  at: number;
}

export interface WorktreeDiffFile {
  path: string;
  status: string;
  insertions: number;
  deletions: number;
  hunk: string;
}

export interface WorktreeDiff {
  name: string;
  from_sha: string;
  to_sha: string;
  files: WorktreeDiffFile[];
}

// Per-entry shape returned by GET /api/git/worktrees/:name/tree.
// Mirrors `WorktreeTreeEntry` in `crates/dashboard/src/data.rs`.
export interface WorktreeTreeEntry {
  /// Basename (no path separators).
  name: string;
  /// Forward-slash root-relative path.
  path: string;
  /// "file", "dir", "symlink", or "other".
  kind: string;
  /// Bytes (regular files only). `null` for directories /
  /// symlinks / other.
  size: number | null;
}

export interface WorktreeTree {
  name: string;
  /// Path relative to the worktree root that was listed
  /// (`""` ⇒ root). Forward-slash separated.
  path: string;
  entries: WorktreeTreeEntry[];
  /// `true` when the listing was capped by the per-request
  /// entry budget; the caller should refine the path.
  truncated: boolean;
}

export interface WorktreeFile {
  name: string;
  path: string;
  size: number;
  /// "utf8" or "base64".
  encoding: string;
  /// File content (UTF-8 string or base64 of raw bytes).
  content: string;
}

// Server-Sent Event payload from /api/sessions/:id/stream.
//
// Wire contract — `INV-DASHBOARD-STREAM-ENVELOPE-01` (see
// `raxis/specs/invariants.md`):
//
//   data: {"at_ms": <u64>, "kind": <string>, "payload": <any>}
//   id:   <at_ms>     ← duplicated so EventSource's auto-reconnect
//                       resume via `Last-Event-ID` works.
//
// Data frames DO NOT set a custom `event:` field; they reach the
// browser as default-`message` SSE events so `EventSource.onmessage`
// picks every frame up uniformly regardless of how many kinds the
// kernel publishes. The previous wire (`event: <kind>` + payload-
// only `data:`) forced the FE to enumerate every kind via
// `addEventListener` and silently dropped any kind it had not pre-
// registered — fatal when the audit→stream bridge fans ~80 audit
// event kinds onto the per-session stream.
//
// Control frames keep their typed `event:` names so the FE can
// branch on protocol semantics rather than parsing JSON:
//
//   * `event: tail-complete`     — backend finished the file-ring
//     replay; live frames begin next.
//   * `event: lagged`            — slow subscriber dropped `data`
//     events (the data line carries the lag count).
//   * `event: closed`            — publisher dropped the broadcast
//     (session terminated or no live source attached).
//   * `event: kernel-shutdown`   — kernel orderly shutdown; the FE
//     suppresses EventSource auto-reconnect on this frame.
//   * `event: keep-alive`        — axum's SSE keep-alive heartbeat
//     emitted every 15 s; ignored by the renderer.
export interface StreamEventEnvelope {
  /// Unix milliseconds timestamp from the wire `at_ms` (also
  /// duplicated as the SSE `id:` field).
  at_ms: number;
  /// Event kind. For audit-bridge frames this is the audit
  /// `event_kind` PascalCase string (`IntentAccepted`, …); for
  /// future gateway frames this'll be `model_chunk` / `tool_call`
  /// / `tool_result` / `terminal` / `heartbeat`. The wire is
  /// open — new kinds may appear without a frontend release.
  kind: string;
  /// Free-form structured payload parsed from the SSE `data:`
  /// envelope. Audit-bridge frames carry `{seq, event_id,
  /// initiative_id, task_id, payload}` so operators can deep-link
  /// to the audit-chain row.
  payload: unknown;
}
