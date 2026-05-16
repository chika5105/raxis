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
  /// Lifecycle annotations rendered by `<LifecycleTimeline>`.
  /// `INV-DASHBOARD-LIFECYCLE-CAUSALITY-01`.
  annotations?: LifecycleAnnotation[];
  /// Most recent annotation — surfaced on the global tasks
  /// index "Lifecycle" column for one-line summaries.
  latest_annotation?: LifecycleAnnotation | null;
  /// `tasks.review_verdict` mirror — `"Approved"` /
  /// `"Rejected"` / null. Powers the colour-coded badge in
  /// `<ReviewerVerdictPanel>`.
  review_verdict?: string | null;
  /// `tasks.last_critique` mirror — multi-reviewer aggregated
  /// critique text. Rendered as a collapsible block beneath
  /// the verdict badge.
  last_critique?: string | null;
  /// One row per reviewer downstream of this executor task,
  /// parsed from the audit chain's `SubmitReview` /
  /// `ReviewAggregationCompleted` events.
  reviewer_panel_results?: ReviewerPanelEntry[];
}

/// One reviewer's result against an executor task, surfaced
/// in `<ReviewerVerdictPanel>` so the operator sees per-
/// reviewer agreement / disagreement at a glance.
export interface ReviewerPanelEntry {
  reviewer_task_id: string;
  verdict: string;
  /// First three lines of the reviewer's critique. The full
  /// text lives on the per-reviewer task detail page.
  critique_excerpt: string;
  completed_at: number;
}

/// Wire shape for `LifecycleAnnotation` (Rust enum with
/// `#[serde(tag="kind", rename_all="snake_case")]`).
///
/// Each variant is a discriminated union over `kind`. The FE
/// dispatches on `kind` to pick a `<LifecycleAnnotation>`
/// renderer (one tsx component per variant).
export type LifecycleAnnotation =
  | {
      kind: "retry_review_reject";
      retry_number: number;
      triggered_by_reviewer_task_id: string;
      verdict: string;
      critique: string;
      review_reject_count: number;
      max_review_rejections: number;
      crash_retry_count: number;
      max_crash_retries: number;
      prior_activation_id: string;
      new_activation_id: string;
      prior_head_sha?: string | null;
      new_head_sha?: string | null;
      ts_unix: number;
    }
  | {
      kind: "retry_crash";
      retry_number: number;
      exit_code?: number | null;
      terminal_tool?: string | null;
      max_turns_scaled_from?: number | null;
      max_turns_scaled_to?: number | null;
      crash_retry_count: number;
      max_crash_retries: number;
      ts_unix: number;
    }
  | {
      kind: "retry_validation_reject";
      retry_number: number;
      validator_reason: string;
      validator_detail: unknown;
      validation_reject_count: number;
      max_validation_rejections: number;
      ts_unix: number;
    }
  | {
      kind: "session_revoked_operator";
      revoked_by: string;
      revoked_by_display_name?: string | null;
      intent_kind?: string | null;
      ts_unix: number;
    }
  | {
      kind: "session_revoked_self_exit";
      terminal_tool?: string | null;
      exit_code?: number | null;
      console_log_path?: string | null;
      ts_unix: number;
    }
  | {
      kind: "initiative_blocked";
      block_reason: string;
      blocking_task_id?: string | null;
      ts_unix: number;
    }
  | {
      kind: "orchestrator_gap";
      activation_id: string;
      task_id: string;
      predecessors_completed_at: Array<[string, number]>;
      wait_seconds: number;
    };

/// Wire shape for `GET /api/orchestrator-gaps`.
export interface OrchestratorGapsResponse {
  gaps: LifecycleAnnotation[];
  generated_at: number;
}

/// Wire shape for one row of `GET /api/recent-sessions`.
/// Mirrors `raxis_dashboard::data::RecentSessionEntry`.
export interface RecentSessionEntry {
  session_id: string;
  agent_type: string;
  task_id?: string | null;
  initiative_id?: string | null;
  created_at: number;
  terminated_at?: number | null;
  terminated_reason?: string | null;
  final_annotation?: LifecycleAnnotation | null;
  capture_bytes: number;
}

/// Wire shape for one record returned by
/// `GET /api/tasks/:task_id/llm-turns`. Mirrors
/// `raxis_dashboard::data::TaskLlmTurnView` field-for-field.
/// `INV-DASHBOARD-LLM-TURN-PANEL-WIRE-SHAPE-01`.
export interface TaskLlmTurnView {
  /// Monotonic 1-indexed turn number — one per call to
  /// `TaskLlmCapture::append`. Ordered so the FE can render
  /// "Turn 1", "Turn 2", … without sorting.
  turn_number: number;
  /// Unix-seconds timestamp the turn was captured.
  ts_unix: number;
  /// Provider model id (e.g. `claude-sonnet-4-5-20250929`,
  /// `gpt-4o`). Empty when the response body was non-JSON or
  /// the field was absent.
  model: string;
  /// `"system"` / `"user"` / `"assistant"` / `"tool"`. Empty
  /// when the response body envelope does not carry a top-
  /// level `role` (e.g. OpenAI's `chat.completion`, where
  /// `role` lives inside `choices[]`).
  role: string;
  /// Fully-parsed request payload (typed `unknown` so the FE
  /// renders it generically). `null` when the kernel-side tap
  /// could not capture or parse the bytes.
  request: unknown;
  /// Fully-parsed response payload. On parse failure the BE
  /// falls back to a JSON string of the raw body so the
  /// operator still sees the bytes.
  response: unknown;
  /// Per-turn token usage. `cache_hit_ratio` is derived FE-
  /// side from `cache_read_input_tokens / (cache_read_input_tokens
  /// + cache_creation_input_tokens + input_tokens)` — the wire
  /// only carries the raw counts.
  input_tokens?: number | null;
  output_tokens?: number | null;
  cache_creation_input_tokens?: number | null;
  cache_read_input_tokens?: number | null;
  /// Wall-clock ms between request issue and response
  /// completion. Surfaced for prompt-cache effectiveness
  /// analysis.
  latency_ms?: number | null;
  /// Carry-overs from the BE wire view — useful for global
  /// "recent LLM activity" cross-task views and for
  /// surfacing transport / truncation metadata in the per-
  /// turn panel.
  task_id: string;
  session_id?: string | null;
  fetch_id: string;
  status_code?: number | null;
  /// Original response body length, before per-record body
  /// cap truncation. Rendered alongside the truncation
  /// badge.
  original_body_bytes?: number;
  /// `true` when the response body was truncated at the
  /// kernel-side cap. The panel renders a suffix on the
  /// Response payload header.
  body_truncated?: boolean;
  /// Structured upstream error category from the gateway
  /// (e.g. `"transport_timeout"`). When set the panel
  /// renders an "upstream error" badge.
  error?: string | null;
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

/// `GET /api/initiatives/:id/plan` response body — the original
/// submitted `plan.toml` for one initiative byte-for-byte.
///
/// Source of truth: `raxis_dashboard::data::InitiativePlanView`.
/// `INV-DASHBOARD-INITIATIVE-PLAN-VISIBLE-01`: the FE renders
/// `submitted_toml` verbatim (no re-parse / re-serialize) so the
/// operator-visible bytes match the audit-chain hash they
/// pre-approved.
export type ApprovalStatus = "approved" | "pending" | "rejected";

export interface InitiativePlanView {
  initiative_id: string;
  /// Lowercase-hex SHA-256 of the on-disk plan artifact. `null`
  /// for legacy V1 rows where the column was empty.
  plan_sha256: string | null;
  /// Lowercase-hex SHA-256 of the V2.1 plan bundle the operator
  /// sealed. `null` for V1 plans (which used
  /// `signed_plan_artifacts` and did not seal a bundle).
  bundle_sha256: string | null;
  /// The original submitted plan TOML. Byte-for-byte identical
  /// to what the operator submitted (forensic fidelity).
  submitted_toml: string;
  submitted_toml_bytes: number;
  submitted_at_unix: number;
  /// Operator pubkey fingerprint (lowercase hex) of whoever
  /// sealed the bundle. `null` for V1 plans (no separated
  /// fingerprint at the artifact layer).
  submitted_by: string | null;
  approval_status: ApprovalStatus;
  approved_at_unix: number | null;
}

// ---------------------------------------------------------------------------
// Credentials view — `INV-DASHBOARD-CREDENTIAL-*`.
//
// The dashboard surfaces every credential file the kernel knows
// about (per-initiative + system-wide) in a default-MASKED view:
// the listing endpoint carries metadata only — name, proxy type,
// mount alias, format hint, byte size, SHA-256 prefix, on-disk
// path. Plaintext is fetched on demand through the separate
// `*/reveal` POST endpoint, which is admin-role-gated, audited
// before response, and rate-limited per operator.
//
// Source of truth: `raxis_dashboard::data::CredentialMetadata`
// and `raxis_dashboard::data::CredentialReveal`. These mirrors
// MUST stay in sync — the wire shape has no `plaintext` field on
// the listing endpoint by spec, and we MUST NOT add one here as
// a defence-in-depth check against accidental drift.
// ---------------------------------------------------------------------------

/// One credential row returned by either the per-initiative
/// (`GET /api/initiatives/:id/credentials`) or system-wide
/// (`GET /api/system/credentials`) listing endpoint.
///
/// **NEVER** carries plaintext. The reveal endpoint
/// (`POST .../reveal`) is the only sanctioned path that
/// returns the bytes, and it returns them via the disjoint
/// [`CredentialReveal`] shape.
export interface CredentialMetadata {
  name: string;
  proxy_type: string;
  mount_as?: string | null;
  format_hint: string;
  upstream_host_port?: string | null;
  byte_size: number;
  sha256_prefix?: string | null;
  loaded_from_path?: string | null;
  is_revealable: boolean;
  /// Wire-stable role string the operator MUST hold to reveal
  /// (`"admin"`). Consumed verbatim by the FE so the reveal
  /// button is disabled — with the right tooltip — for
  /// `read`-role operators.
  reveal_required_role: string;
}

/// Wire shape returned by both listing endpoints. Wraps a
/// `Vec<CredentialMetadata>` so future fields (pagination
/// markers, total counts) can be added without breaking the
/// FE.
export interface CredentialListResponse {
  credentials: CredentialMetadata[];
}

/// Successful reveal response. Carries:
///
///   * `plaintext` — UTF-8 string for `encoding == "utf8"`
///     credentials, base64-encoded bytes for `encoding ==
///     "base64"` (binary credentials).
///   * `expires_at_unix` — wall-clock auto-hide deadline. The
///     FE MUST honour this regardless of operator activity
///     (`INV-DASHBOARD-CREDENTIAL-AUTO-HIDE-01`). Per-initiative
///     credentials get +30 s; system credentials (Anthropic,
///     other provider keys) get +15 s.
///   * `sha256_prefix` — first 8 lowercase hex chars of the
///     SHA-256 of the bytes, surfaced in the reveal banner so
///     the operator can sanity-check what they're looking at.
export interface CredentialReveal {
  name: string;
  plaintext: string;
  encoding: "utf8" | "base64";
  byte_size: number;
  expires_at_unix: number;
  sha256_prefix: string;
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
  /// Lifecycle annotations rendered inline in the session
  /// stream timeline. `INV-DASHBOARD-LIFECYCLE-CAUSALITY-01`.
  annotations?: LifecycleAnnotation[];
  /// Most recent annotation, surfaced in compact session list
  /// rows so an operator sees self-exit vs operator-revoke
  /// without drilling in.
  latest_annotation?: LifecycleAnnotation | null;
}

/// One record from the per-session lifecycle capture ring
/// (`raxis-dashboard-kernel::SessionCapture`). Surfaced by
/// `GET /api/sessions/:id/capture?limit=N`. The post-mortem
/// surface persists past session termination — the file ring
/// lives in `<data_dir>/session-capture/<session_id>.ndjson`
/// and is evicted only when the bounded ring rolls.
/// INV-DASHBOARD-SESSION-CAPTURE-* (specs/v3/session-capture.md).
export interface SessionCaptureView {
  /// Owning session id (matches the URL path parameter).
  session_id: string;
  /// Record kind discriminator — `fsm_transition`,
  /// `audit_event`, `ksb_snapshot`, etc. The FE renders unknown
  /// kinds generically so the kernel can land new kinds
  /// without an FE bump.
  kind: string;
  /// Unix seconds when the observer appended the record.
  ts_unix: number;
  /// Free-form payload. Generic object — every audit-event
  /// mirror has at minimum `{event_kind, seq, event_id, …}`;
  /// FSM transitions are `{from, to, reason}`; etc.
  payload: Record<string, unknown>;
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

/// Wire shape served by `GET /api/health/kernel-lifecycle`.
///
/// Mirrors `raxis_dashboard::routes::health::KernelLifecycleResponse`
/// in the kernel — see also `raxis-supervisor::sentinel::Sentinel`
/// for the on-disk source of truth and `self-healing-supervisor.md
/// §5.2` for the contract. The FE matches on `status` + optional
/// `sub_state` to render `<KernelLifecycleBanner>`; every other
/// field is metadata for the popover detail view.
///
/// `status` is one of `"Healthy"`, `"Restarting"`, `"Halted"`.
/// `sub_state` is `"CircuitOpen"`, `"OperatorStop"`,
/// `"OperatorStopForced"`, `"SupervisorGone"` (only set when
/// `status === "Halted"`). The banner also surfaces a stale-data
/// note when `fresh === false` so an operator who is staring at
/// an old sentinel knows the numbers shouldn't be trusted.
export interface KernelLifecycleResponse {
  status: "Healthy" | "Restarting" | "Halted" | string;
  sub_state?:
    | "CircuitOpen"
    | "OperatorStop"
    | "OperatorStopForced"
    | "SupervisorGone"
    | string
    | null;
  attempt_n: number;
  max_attempts: number;
  last_restart_reason?: string | null;
  last_restart_unix_ts: number;
  attempts_in_window: number;
  window_secs: number;
  supervisor_pid: number;
  kernel_pid: number;
  updated_at_unix_secs: number;
  fresh: boolean;
  /// V2.5 `self-healing-supervisor.md §3.5` /
  /// `INV-SUPERVISOR-AUTO-RESUME-ON-CLEAN-RESTART-01` — summary
  /// of the most recent supervisor-aware auto-resume sweep.
  /// Absent when the kernel has never been booted under the
  /// supervisor, when the per-restart summary file
  /// (`<data_dir>/last_auto_resume.json`) is missing or
  /// unparseable, or when the recorded episode is older than
  /// 5 minutes (`AUTO_RESUME_VISIBILITY_WINDOW_SECS` on the
  /// kernel side). The banner uses this to render a transient
  /// post-restart pill — green for full auto-resume, amber when
  /// at least one task stayed paused.
  auto_resume?: KernelAutoResumeSummary | null;
}

/// Serde-stable summary of one supervisor-aware auto-resume
/// sweep. Mirrors `raxis_dashboard::routes::health::
/// KernelAutoResumeSummary`, which is read from
/// `<data_dir>/last_auto_resume.json` (written by the kernel
/// boot's `recovery::reconcile_after_supervisor_restart` caller
/// in `kernel/src/main.rs`).
export interface KernelAutoResumeSummary {
  /// Tasks the sweep transitioned BlockedRecoveryPending → Admitted.
  resumed: number;
  /// Tasks skipped because the initiative is operator-quarantined
  /// (`initiative_quarantines` row exists for the initiative).
  skipped_quarantined: number;
  /// Tasks skipped because they were ALREADY at
  /// `BlockedRecoveryPending` BEFORE this boot's recovery sweep
  /// (preserve operator pre-existing block).
  skipped_pre_existing_block: number;
  /// Tasks the sweep tried to resume but the FSM transition or
  /// audit-emit failed; they remain at `BlockedRecoveryPending`
  /// and need an operator `task resume`.
  transition_failed: number;
  /// Stable identifier shared by every
  /// `TaskAutoResumedAfterSupervisorRestart` event from this
  /// episode. Lets the dashboard link the banner pill to the
  /// matching audit rows.
  supervisor_restart_id: string;
  /// Wallclock unix-seconds the kernel wrote the file. The
  /// dashboard handler suppresses the field if this is more
  /// than `AUTO_RESUME_VISIBILITY_WINDOW_SECS` (5 minutes) ago.
  recorded_at_unix_secs: number;
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
  /// `tool_result` / `terminal` / `heartbeat`. The wire is
  /// open — new kinds may appear without a frontend release.
  kind: string;
  /// Free-form structured payload parsed from the SSE `data:`
  /// envelope. Audit-bridge frames carry `{seq, event_id,
  /// initiative_id, task_id, payload}` so operators can deep-link
  /// to the audit-chain row.
  payload: unknown;
}
