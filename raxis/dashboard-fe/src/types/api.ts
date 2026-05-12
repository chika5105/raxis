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
// Wire shape (per raxis/crates/dashboard/src/routes/sessions.rs
// and raxis-dashboard's `StreamEvent`):
//
//   event: <kind>      ← SSE event name, also stamped into `kind`
//   id:    <at_ms>     ← unix milliseconds (lastEventId on the
//                        browser side)
//   data:  <payload>   ← the `payload` field's JSON ONLY, NOT
//                        the full envelope
//
// Control frames (no `payload`, emitted by the backend SSE
// handler in `routes::sessions::stream::build_sse_stream`):
//
//   * `event: tail-complete` — backend has finished replaying
//     the file-ring tail; live frames begin next.
//   * `event: lagged`        — slow subscriber dropped `data`
//     events (the data line carries the lag count).
//   * `event: closed`        — publisher dropped the broadcast
//     (session terminated or no live source attached).
//   * `event: keep-alive`    — axum's SSE keep-alive heartbeat
//     emitted every 15 s; ignored by the renderer.
//
// The renderer constructs an in-browser `StreamEventEnvelope`
// from those three SSE fields (kind / at_ms / payload). It does
// NOT expect the backend to pack the whole envelope into `data:`.
export interface StreamEventEnvelope {
  /// Unix milliseconds timestamp from the SSE `id:` field.
  at_ms: number;
  /// Event kind (`token` / `tool_call` / `tool_result` /
  /// `terminal` / `model_chunk` / `error` / `lagged` / `closed`
  /// / `tail-complete` / ...). The wire is open — new kinds may
  /// appear without a frontend release.
  kind: string;
  /// Free-form structured payload parsed from the SSE `data:`
  /// line. Shape depends on `kind`.
  payload: unknown;
}
