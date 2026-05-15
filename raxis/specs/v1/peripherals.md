# RAXIS — Part 3: Planner, Gateway, and Verifier Specifications

> **Scope:** The three non-kernel processes that interact with the kernel over UDS. §3.1 covers the planner IPC contract and system-prompt API. §3.2 covers the gateway wire format. §3.3 covers the verifier subprocess contract.
>
> **Navigation:** [README](../../README.md) | [Part 2 Core](kernel-core.md) | [Part 2 Store](kernel-store.md) | [Planner API](planner-api.md) | [Part 4](cli-ceremony.md)
>
> **Authority:** Where this file and [`kernel-core.md`](kernel-core.md) conflict on IPC message shapes, this file wins — it is the client-facing contract. Where this file and [`kernel-store.md`](kernel-store.md) conflict on DDL-backed fields (e.g. session token format, sequence numbers), [`kernel-store.md`](kernel-store.md) wins.

> **Normative wire format — single source of truth:**
> All IPC between kernel, planner, gateway, and verifier uses **bincode-encoded Rust types preceded by a 4-byte little-endian unsigned length prefix** (the prefix itself is excluded from the byte count it announces). The codec is **`bincode = "=2.0.1"` (exact pin) using `bincode::config::standard()`** — i.e. variable-length integer encoding (LEB128 / varint), little-endian byte order, no struct/field name metadata on the wire (variants and fields are positional). `bincode::serde::encode_to_vec` / `decode_from_slice` are the canonical entry points; the `serde` feature is enabled in `raxis-ipc/Cargo.toml` (workspace dep declared in `raxis/Cargo.toml`). This is implemented in `raxis-ipc::frame`.
>
> **Why `=2.0.1` exactly, and why not bincode 1.x or 3.x.**
>
> - **Not 1.x.** Bincode 1.x and 2.x produce wire-incompatible byte streams under their respective default configs (1.x defaults to fixed-width `u64` length encoding; 2.x defaults to varint via `Configuration::standard()`). v1 wants the smaller, named, varint format.
> - **Not 3.x.** As of 2026, the `bincode = "3.0.0"` artifact on crates.io is published by a downstream fork (`Apich-Organization/bincode-next`) — the original `bincode-org/bincode` repository was **archived in August 2025** and the original maintainer ceased development. Critically, 3.x's `config::standard()` is **wire-incompatible** with 2.x's `config::standard()`; only 3.x's `config::legacy()` round-trips with 2.x. Pinning 3.x would (a) bind the v1 protocol to an unaudited downstream organisation's evolution, and (b) silently break wire format if a future maintainer changes 3.x defaults. v1 stays on the last release from the original org.
> - **`=2.0.1` (exact pin, no caret).** The `=` operator in the workspace Cargo.toml prevents an accidental jump to a hypothetical `2.0.2` or `2.1.0` patch from a downstream republisher. The first implementation sprint MUST re-evaluate this pin against the state of the post-archival Rust ecosystem at that time; any codec change requires a §3 amendment AND a wire-compat regression test that round-trips every `IpcMessage` variant against a captured `2.0.1` baseline.
>
> Implementations MUST NOT use `bincode::config::legacy()` (the 1.x compatibility config) on the wire — that variant exists for migration from 1.x stores only and is not part of the v1 IPC contract. There is no schema version field in v1; the `IpcMessage` enum tag (positional `u32` discriminant per bincode 2 encoding) is the only versioning surface.
>
> **Frame format (normative pseudo-Rust):**
>
> ```rust
> // raxis-ipc/src/frame.rs (normative)
> pub const FRAME_MAX_BYTES: usize = 16 * 1024 * 1024; // 16 MiB hard cap; oversized frame → connection close
> pub fn write_frame<W: AsyncWrite + Unpin, T: serde::Serialize>(w: &mut W, msg: &T) -> io::Result<()> {
>     let body = bincode::serde::encode_to_vec(msg, bincode::config::standard())
>         .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
>     if body.len() > FRAME_MAX_BYTES { return Err(io::Error::new(io::ErrorKind::InvalidData, "frame too large")); }
>     let len = u32::try_from(body.len())
>         .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "frame > u32::MAX"))?;
>     w.write_all(&len.to_le_bytes()).await?;
>     w.write_all(&body).await
> }
> pub async fn read_frame<R: AsyncRead + Unpin, T: serde::de::DeserializeOwned>(r: &mut R) -> io::Result<T> {
>     let mut len_buf = [0u8; 4];
>     r.read_exact(&mut len_buf).await?;
>     let len = u32::from_le_bytes(len_buf) as usize;
>     if len > FRAME_MAX_BYTES { return Err(io::Error::new(io::ErrorKind::InvalidData, "advertised length exceeds FRAME_MAX_BYTES")); }
>     let mut body = vec![0u8; len];
>     r.read_exact(&mut body).await?;
>     let (msg, consumed) = bincode::serde::decode_from_slice(&body, bincode::config::standard())
>         .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
>     if consumed != len { return Err(io::Error::new(io::ErrorKind::InvalidData, "trailing bytes in frame")); }
>     Ok(msg)
> }
> ```
>
> All JSON objects in this document are **human-readable projections** of the underlying `raxis-ipc` types for specification clarity — they are not the wire encoding. An implementation that sends bare JSON on the UDS is non-conformant. Where a JSON field name below differs from the Rust struct field name in `raxis-ipc`, the Rust name wins (bincode 2 with `standard()` config does not transmit field names anyway, so the JSON projection's field naming is purely a documentation convention; only the positional layout of the Rust struct is observable on the wire).

---

## §3.1 — Planner IPC Contract

### What the planner is

The planner is an LLM session running as a subprocess of or alongside the kernel. It is **not** a compiled binary in the RAXIS repository — it is the model-side participant in the kernel IPC protocol. Part 3.1 is the normative contract for that protocol: what the planner must send, what it will receive, and how it must behave.

The planner system prompt is assembled by the kernel (`prompt/assembler.rs`) and injected at session start. The machine-readable API specification — the portion of the system prompt that defines error codes, retry rules, and remediation actions — is in [`planner-api.md`](planner-api.md). That file is designed to be injected verbatim.

### Session lifecycle

```text
1. Kernel spawns planner subprocess (or planner connects to planner.sock)
2. Kernel calls create_session(Role::Planner, worktree_root, ...) → session_token
3. Kernel assembles system prompt via prompt::assemble(session_id) → injects into planner context
4. Planner loop:
     a. Submit IntentRequest (with session_token + sequence_number)
     b. Receive IntentResponse (Accepted or Rejected)
     c. If Rejected: read error code → apply remediation → retry or escalate
     d. If CompleteTask accepted: session ends for this task
5. On all tasks complete: planner session ends; kernel revokes session_token
```

The planner must not assume it can reuse a session across initiatives. One session = one initiative scope.

> **INV-PLANNER-SPAWN (normative):** The kernel **never autonomously decides to start a planner**. After `ApprovePlan` the kernel admits tasks and waits. An agent only begins executing when an operator (a) calls `CreateSession` to mint a session token and (b) independently starts a planner process that connects to `planner.sock` with that token. The two decisions — *"is this plan valid?"* and *"should an agent start now?"* — are intentionally separate and both require explicit operator action. This is a hard architectural invariant, not an implementation choice: autonomous kernel-initiated planner spawning would bypass the human-in-the-loop checkpoint between plan approval and agent execution, violating the failure-closed model. Implementations MUST NOT add logic that automatically spawns a planner subprocess upon plan approval or task state transitions.

### `IntentRequest` wire shape

> **Encoding reminder:** This JSON is an illustrative projection of `IpcMessage::IntentRequest { .. }` in `raxis-ipc`. On-wire: length-prefixed frame per `raxis-ipc::frame`.

```json
{
  "session_token":    "<256-bit hex>",
  "sequence_number":  42,
  "envelope_nonce":   "<16-byte hex, unique per message>",
  "intent_kind":      "SingleCommit",
  "task_id":          "<task-id from signed plan>",
  "base_sha":         "<40-char hex commit OID>",
  "head_sha":         "<40-char hex commit OID>",
  "submitted_claims": [],
  "justification":    "<free text, max 2048 chars; required for ReportFailure>",
  "idempotency_key":  "<uuid-v4; optional; for safe retry>"
}
```

**Field rules:**
- `sequence_number` — must be exactly `prev_accepted_sequence + 1`. Gaps or reuse → `UNAUTHORIZED`.
- `envelope_nonce` — 16 random bytes, hex. Must be globally unique per `(session_id, nonce)` pair within the nonce cache TTL (§2.5.1 Table 16). Reuse → `UNAUTHORIZED`.
- `base_sha` and `head_sha` — required for all intent kinds except `ReportFailure`. For `CompleteTask`, `base_sha` is accepted but ignored by the kernel (see [`kernel-store.md`](kernel-store.md) §2.5.8 `base_sha` disposition). For `SingleCommit`, `base_sha == head_sha` is a valid "no committed changes yet" intent (empty diff — path check passes vacuously per §2.5.8 edge-case table). For non-empty `SingleCommit` (`base_sha != head_sha`): the kernel enforces `parent(head_sha) == base_sha` via **`vcs::rev_parse_parent`** ([`kernel-core.md`](kernel-core.md) Part 2.2 §`src/vcs/diff.rs` — normative command `git -C <worktree_root> rev-parse --verify <head_sha>^1`; root-commit and missing-SHA edge cases mapped to `HandlerError::InvalidShaRange`) — i.e. exactly one new commit on top of `base_sha`. Submitting a `base_sha` that is an ancestor of `head_sha` but not its direct parent is rejected with `HandlerError::InvalidShaRange`. **This means `SingleCommit` is truly single-commit: one intent = one commit. Multi-commit ranges require a different `IntentKind` (not in v1).**
- `submitted_claims` — **deprecated; always `[]`; contents discarded by the kernel.** The kernel auto-derives all claims from its own witness records (`gates/mod.rs` Step 2.5). Any claims the planner populates in this field are silently dropped. The field is retained on the wire for backward compatibility but has no semantic effect. See [`kernel-core.md`](kernel-core.md) §`src/gates/mod.rs` Step 2.5 for the auto-derivation contract.
- `justification` — required and non-empty for `IntentKind::ReportFailure`. Ignored for all other kinds.
- `idempotency_key` — if provided, the kernel returns the same `IntentResponse` on a duplicate submission with the same key (within the session). Absent → no idempotency guarantee.

**`intent_kind` valid values (v1):**

| Value | Description |
|---|---|
| `"SingleCommit"` | Exactly one committed change on top of `base_sha`. Kernel enforces `parent(head_sha) == base_sha` for non-empty ranges (one intent = one commit). Empty diff (`base_sha == head_sha`) is permitted. Multi-commit ranges are not supported in v1 — a planner that batches commits must issue one `SingleCommit` per commit or use `IntegrationMerge` for the final merge. |
| `"IntegrationMerge"` | A merge commit integrating agent branches. Subject to the 5-predicate topology check (§2.5.8). |
| `"CompleteTask"` | Asserts the task is done. Triggers path closure check + gate closure check. |
| `"ReportFailure"` | Planner self-reports inability to complete the task. Transitions `Running → Failed`. Requires `justification`. |

### `IntentResponse` wire shape

> **Encoding reminder:** This JSON is the normative wire projection of `IpcMessage::KernelResponse(IntentResponse)` in `raxis-ipc`. The structural shape mirrors the Rust enum normatively defined in [`philosophy.md`](philosophy.md) `crates/types/src/intent.rs` (two variants — `Accepted` and `Rejected`); the `outcome` JSON string is the discriminant. Wire fields are partitioned into:
>
> - **Envelope fields** (added by `raxis-ipc`'s frame serialiser, common to every IPC message — see [`philosophy.md`](philosophy.md) `crates/types/src/envelope.rs`): `sequence_number`. The planner correlates a response to its prior request by matching `sequence_number`; the kernel does not echo `task_id` on the wire because correlation is already complete via the envelope.
> - **Payload fields** (the variant body): every field shown below other than `sequence_number`.

Accepted projection:

```json
{
  "sequence_number":       42,
  "outcome":               "Accepted",
  "task_state":            "Running",
  "remaining_budget":      { "admission_units": 48200 },
  "warn_delegation_stale": false,
  "error_code":            null,
  "error_detail":          null
}
```

Rejected projection:

```json
{
  "sequence_number":       42,
  "outcome":               "Rejected",
  "task_state":            "Running",
  "remaining_budget":      null,
  "warn_delegation_stale": null,
  "error_code":            "FAIL_PATH_POLICY_VIOLATION",
  "error_detail":          null
}
```

**Field rules — exhaustive (every wire field is listed here so the projection cannot drift from the Rust type):**

| Field | Origin | Variant | Type / values | Rule |
|---|---|---|---|---|
| `sequence_number` | envelope | both | u64 | Matches the `sequence_number` of the `IntentRequest` this is responding to. |
| `outcome` | discriminant | both | `"Accepted"` \| `"Rejected"` | Never a partial state. Maps to the Rust enum variant. |
| `task_state` | payload | both | `TaskState` enum string: `Admitted`, `Running`, `GatesPending`, `Completed`, `Failed`, `Aborted`, `Cancelled`, `BlockedRecoveryPending` | **Always present** on both variants. Reflects the task's state at response time — post-transition on `Accepted`, last-committed-state on `Rejected` (the binding `UPDATE` rolls back on early rejections). The planner uses this on `Rejected` to choose a retry strategy (e.g. `FAIL_TASK_NOT_RUNNING` with `task_state: GatesPending` ⇒ wait for witnesses; with `task_state: BlockedRecoveryPending` ⇒ wait for operator). |
| `remaining_budget` | payload | `Accepted` only | `BudgetSnapshot` JSON object, or `null` on `Rejected` | The lane's budget snapshot after `consume_budget` ran for this intent (or after the existing-reservation branch decided not to charge again — see [`kernel-core.md`](kernel-core.md) `handlers/intent.rs` "Budget check and reservation"). The inner shape is the JSON serialisation of the `BudgetSnapshot` Rust struct ([`philosophy.md`](philosophy.md) `crates/types/src/intent.rs`); units are admission units per [`kernel-core.md`](kernel-core.md) §3.5 / [`kernel-store.md`](kernel-store.md) §2.5.7. The planner uses this to self-throttle: estimate the cost of the next intent and avoid submitting if `remaining_budget < estimate`. **Always `null` on `Rejected`** — rejected intents do not consume budget, so there is no post-consume snapshot to report. |
| `warn_delegation_stale` | payload | `Accepted` only | `bool`, or `null` on `Rejected` | `true` iff `evaluate_claims` took the `SufficientStale` grace use to admit this intent. The planner must renew the delegation before the next gated action. **Always `null` on `Rejected`** — no grace use was consumed. |
| `error_code` | payload | `Rejected` only | `PlannerErrorCode` enum string, or `null` on `Accepted` | Coarse rejection reason. Full enum values + remediation in [`planner-api.md`](planner-api.md). Maps from the Rust `Rejected.reason` field. |
| `error_detail` | payload | `Rejected` only | `string` (≤256 chars), or `null` | **INV-08 rule (definitive for v1):** `error_detail` is `null` for every rejection code **except** `FAIL_POLICY_VIOLATION`. For `FAIL_POLICY_VIOLATION` only, `error_detail` contains exactly one string from the approved generic-template set — the `PlannerErrorTemplate` enum in `raxis-types/src/error.rs`. Templates are fixed, version-controlled strings — no runtime interpolation, no file paths, no policy rule names, no glob patterns. The planner must not parse `error_detail` for logic decisions — it is an operator debugging aid only. Maps from the Rust `Rejected.error_detail: Option<PlannerErrorTemplate>`. |

**Cross-variant exclusivity (validator rule):** `outcome == "Accepted"` ⇒ `error_code` and `error_detail` are `null`, and `remaining_budget` and `warn_delegation_stale` are non-`null`. `outcome == "Rejected"` ⇒ `remaining_budget` and `warn_delegation_stale` are `null`, and `error_code` is non-`null` (with `error_detail` populated only for `FAIL_POLICY_VIOLATION`). Receivers must reject responses that violate this exclusivity as malformed (treat as `INVALID_REQUEST` from a wire-integrity standpoint).

### Retry semantics

All rejections are **non-terminal** for the task unless the planner submits `ReportFailure`. The planner may correct the underlying issue and resubmit. Rules:

| Error code | Retryable | Planner action before retry |
|---|---|---|
| `FAIL_PATH_POLICY_VIOLATION` | Yes | Revert out-of-scope commits; push corrected `head_sha`; resubmit |
| `FAIL_INVALID_COMMIT_TOPOLOGY` | Yes | Rebase to linearize; push linearized `head_sha`; resubmit |
| `FAIL_INVALID_DIFF` | Yes | Resolve merge conflicts; push clean `head_sha`; resubmit |
| `FAIL_MISSING_WITNESS` | Yes | Wait for verifier runner to deliver witness; resubmit after gate resolves |
| `FAIL_INSUFFICIENT_WITNESS` | Yes | Improve evidence quality; re-run verifier; resubmit |
| `FAIL_BUDGET_EXCEEDED` | Yes (after budget restored) | Wait or submit smaller scope; resubmit |
| `FAIL_UNKNOWN_TASK` | No | Task not in signed plan — cannot be retried |
| `FAIL_TASK_NOT_RUNNING` | Yes (when task becomes runnable) | Wait for predecessors / gate clearance / operator recovery; then resubmit |
| `FAIL_POLICY_VIOLATION` | Context-dependent | Read `error_detail` generic template; escalate if needed |
| `UNAUTHORIZED` | No | Session is invalid; stop. Do not retry with the same session token |
| `FAIL_STALE_BASE` | Yes | Rebase integration branch onto new main HEAD; resubmit |
| `FETCH_DENIED` | Yes (after backoff / policy change) | Fetch denied by allowlist or rate limit — see audit-facing `deny_reason`; adjust URL or wait |
| `INVALID_REQUEST` | Maybe | Malformed IPC payload or unsupported combination — fix request shape; do not treat as policy probe |

The planner **must stop** on `UNAUTHORIZED` — this indicates a session integrity failure, not a recoverable error.

**Operator socket (not planner-facing):** responses on the operator UDS use a separate error vocabulary tuned for CLI ergonomics — these strings are **not** returned on the planner socket and must not be referenced by `PlannerErrorCode`. All operator-side errors share **one** envelope:

> **v1 implementation note:** the canonical (bincode + typed-IDs) shapes
> shown below in `raxis-types/src/operator.rs` describe the **v2
> destination** for the operator IPC. The actual v1 wire is the
> JSON-shape companion in `raxis-types/src/operator_wire.rs`
> (`{"op":"<Variant>","payload":{...}}`), which uses plain strings and
> sends inline plan/sig blobs instead of `PathBuf`s. Both halves of the
> protocol — the kernel-side dispatcher in `kernel/src/ipc/operator.rs`
> AND every CLI command in `cli/src/commands/*` — go through the same
> `operator_wire::OperatorRequest` enum so wire-shape drift cannot
> creep back in. Wire-shape contract tests live in
> `raxis-types::operator_wire::tests` and `cli/tests/operator_wire_shape.rs`.

```rust
// raxis-types/src/operator.rs (normative)

// Inbound from `raxis-cli` over the operator UDS. One frame per request; reply
// is exactly one `OperatorResponse` frame on the same connection.
// Variant order in this enum matches the §2.5.5 operator IPC discriminant table
// in `kernel-store.md` — that table is the source of truth for preconditions,
// state transitions, and `permitted_ops` strings.
enum OperatorRequest {
    // initiatives
    CreateInitiative   { plan_toml_path: PathBuf, plan_sig_path: PathBuf },
    ApprovePlan        { initiative_id: InitiativeId },
    RejectPlan         { initiative_id: InitiativeId, reason: Option<String> },
    AbortInitiative    { initiative_id: InitiativeId, reason: Option<String> },

    // sessions and delegations
    CreateSession      { role: Role, worktree_root: Option<PathBuf>, base_tracking_ref: Option<String>, task_id: Option<TaskId>, lineage_id: LineageId },
    RevokeSession      { session_id: SessionId },
    GrantDelegation    { session_id: SessionId, capability_class: CapabilityClass, delegating_role_id: RoleId, expires_at: UnixSeconds, scope_json: Option<String>, operator_sig: Ed25519Sig },

    // tasks
    RetryTask          { task_id: TaskId },
    ResumeTask         { task_id: TaskId },
    AbortTask          { task_id: TaskId, reason: Option<String> },

    // escalations (full wire shapes for these are in `kernel-store.md` §2.5.5
    // "Escalation approval on the operator socket"; reproduced here as enum tags only)
    ApproveEscalation  { escalation_id: EscalationId, approval_scope: ApprovalScope, operator_sig: Ed25519Sig },
    DenyEscalation     { escalation_id: EscalationId, reason: String },

    // policy
    RotateEpoch        { policy_path: PathBuf, sig_path: PathBuf },

    // step-10 quarantine primitives — see kernel-store.md §2.5.10
    QuarantineInitiative { initiative_id: InitiativeId, reason: Option<String> },
    QuarantinePlansBy    { target_fingerprint: String,  reason: Option<String> },
}

enum OperatorResponse {
    // initiatives
    InitiativeCreated     { initiative_id: InitiativeId, plan_sha256: [u8; 32], created_at: UnixSeconds },
    PlanApproved          { initiative_id: InitiativeId, transitioned_at: UnixSeconds, n_tasks: u32 },
    PlanRejected          { initiative_id: InitiativeId, transitioned_at: UnixSeconds },
    InitiativeAborted     { initiative_id: InitiativeId, transitioned_at: UnixSeconds, n_tasks_cancelled: u32 },
    InitiativeQuarantined { initiative_id: InitiativeId, quarantined_at: UnixSeconds, was_already_quarantined: bool },
    QuarantineSwept       { target_fingerprint: String, newly_quarantined_ids: Vec<InitiativeId>, quarantined_at: UnixSeconds },
    // sessions and delegations
    SessionCreated        { session_id: SessionId, session_token: String /* 64-char lowercase hex */, role: Role, worktree_root: Option<PathBuf>, base_sha: Option<CommitSha>, base_tracking_ref: Option<String>, expires_at: UnixSeconds, bound_task_id: Option<TaskId>, lineage_id: LineageId },
    SessionRevoked        { session_id: SessionId, revoked_at: UnixSeconds },
    DelegationGranted     { delegation_id: DelegationId, granted_at: UnixSeconds, expires_at: UnixSeconds, capability_class: CapabilityClass },
    // tasks
    TaskRetried           { task_id: TaskId, initiative_id: InitiativeId, transitioned_at: UnixSeconds },
    TaskResumed           { task_id: TaskId, prior_state: TaskState, transitioned_at: UnixSeconds },
    TaskAborted           { task_id: TaskId, transitioned_at: UnixSeconds },
    // escalations
    EscalationApproved    { escalation_id: EscalationId, approval_token_id: ApprovalTokenId, transitioned_at: UnixSeconds },
    EscalationDenied      { escalation_id: EscalationId, transitioned_at: UnixSeconds },
    // policy
    EpochAdvanced         { new_epoch_id: u64, n_delegations_marked_stale: u32, n_sessions_invalidated: u32, policy_sha256: [u8; 32] },
    // catch-all error envelope
    Error {
        code: OperatorErrorCode,    // string-tagged enum (see table below) — wire form is the bare code string
        detail: OperatorErrorDetail,// serde-tagged enum, one variant per code, carrying the code's structured fields; never a free-form string
    },
}

enum OperatorErrorDetail {
    // Tag matches the OperatorErrorCode value; field set is fixed per variant.

    // task-state preconditions
    TaskNotResumable    { current_state: TaskState },
    TaskNotRetryable    { current_state: TaskState },
    InitiativeTerminal  { initiative_state: InitiativeState, terminal_criteria: TerminalCriteria },

    // policy-advance failure details (see `cli-ceremony.md` §`epoch advance`):
    PolicySignatureInvalid { artifact_path: PathBuf },
    PolicyEpochReplay      { presented_epoch: u64, current_epoch: u64 },
    PolicyMalformed        { parser_message: String },
    PathOutsideDataDir     { offending_path: PathBuf, data_dir: PathBuf },
    StoreWrite             { sql_error: String },

    // session lifecycle failures (see `cli-ceremony.md` §`session create` / `session revoke`):
    RoleNotOperatorCreatable    { requested_role: Role },
    WorktreeOutsideAllowedRoots { worktree_root: PathBuf, allowed_roots: Vec<PathBuf> },
    BaseRefUnresolved           { ref_string: String, worktree_root: PathBuf, git_stderr: String },
    InvalidLineageId            { offending_value: String, parse_error: String },
    SessionNotFound             { session_id: SessionId },
    SessionAlreadyRevoked       { session_id: SessionId, revoked_at: UnixSeconds },
    SessionInvalid              { session_id: SessionId, reason: SessionInvalidReason /* enum: Revoked | Expired | NotFound */ },
    SessionTaskMismatch         { session_id: SessionId, bound_task: TaskId, attempted_task: TaskId },

    // delegation grant failures (see `cli-ceremony.md` §`delegation grant`):
    UnknownCapabilityClass      { offending_value: String },
    CapabilityAboveCeiling      { role_id: RoleId, capability_class: CapabilityClass, ceiling: Vec<CapabilityClass> },
    DelegationTtlOutOfRange     { requested_ttl_seconds: u64, max_ttl_seconds: u64 },
    DelegationAlreadyActive     { existing_delegation_id: DelegationId, expires_at: UnixSeconds },
    DelegationSignatureInvalid  { proposed_delegation_id: DelegationId, expected_signer: OperatorId },

    // operator authorisation failure (universal across all operator IPC ops):
    OperationNotPermitted  { operator_id: OperatorId, attempted_op: String },
    // ... one variant per code added in future iterations ...
}
```

The `code` field is the machine-stable error identifier (used by automation, scripts, and CI). The `detail` field is a tagged structured value the CLI deserialises and renders to the operator (e.g. `task retry` failing on a `GatesPending` task prints `"Cannot retry: task is in state GatesPending (must be Failed)"`). **Wire-shape rule (normative):** every operator error MUST be returned as `OperatorResponse::Error { code, detail }` where the `detail` variant tag matches the `code`; an `Error` whose `detail` tag does not match its `code` is a kernel bug and the CLI rejects it with a hard-fail "kernel response shape violation" message rather than attempting to interpret it.

The v1 operator-only error codes — each with its `OperatorErrorDetail` variant — are:

| `OperatorErrorCode` (wire string) | `OperatorErrorDetail` variant | Emitted by | Meaning |
|---|---|---|---|
| `FAIL_TASK_NOT_RESUMABLE` | `TaskNotResumable { current_state }` | `recovery::resume_task` precondition check | `task resume` precondition failed — task is not in `BlockedRecoveryPending`. `current_state` carries the actual state. |
| `FAIL_TASK_NOT_RETRYABLE` | `TaskNotRetryable { current_state }` | `lifecycle::retry_task` precondition 1 | `task retry` precondition failed — task is not in `Failed`. `current_state` carries the actual state. |
| `FAIL_INITIATIVE_TERMINAL` | `InitiativeTerminal { initiative_state, terminal_criteria }` | `lifecycle::retry_task` precondition 4 | `task retry` precondition failed — the containing initiative is in a terminal state (`Completed`/`Failed`/`Aborted`). `initiative_state` is the actual terminal state; `terminal_criteria` is the criterion that drove the initiative there (so the operator immediately sees, e.g., that `AllTasksSucceeded` synchronously moved the initiative to `Failed` after the task failed). See [`kernel-core.md`](kernel-core.md) §4.6 `lifecycle::retry_task` precondition 4 and §4.5 "Operator decision on partial failure" for the criterion-dependent applicability table. |
| `FAIL_POLICY_SIGNATURE_INVALID` | `PolicySignatureInvalid { artifact_path }` | `policy_manager::advance_epoch` Phase 0 step 1 | New policy artifact's Ed25519 signature did not verify against the authority pubkey. |
| `FAIL_POLICY_EPOCH_REPLAY` | `PolicyEpochReplay { presented_epoch, current_epoch }` | `policy_manager::advance_epoch` Phase 0 step 1 (loader epoch monotonicity check) | New artifact's `meta.epoch` is not strictly greater than `policy_epoch_history` MAX. |
| `FAIL_POLICY_MALFORMED` | `PolicyMalformed { parser_message }` | `policy_manager::advance_epoch` Phase 0 step 1 (TOML parse / schema check) | New artifact failed TOML parse or required-block validation. |
| `FAIL_PATH_OUTSIDE_DATA_DIR` | `PathOutsideDataDir { offending_path, data_dir }` | `policy_manager::advance_epoch` Phase 0 path canonicalisation | One of `--policy` / `--sig` resolved to a path outside `<data_dir>/policy/`. |
| `FAIL_STORE_WRITE` | `StoreWrite { sql_error }` | `policy_manager::advance_epoch` Phase 1 commit failure | A SQL write inside the Phase 1 transaction failed; the transaction was rolled back. |
| `FAIL_ROLE_NOT_OPERATOR_CREATABLE` | `RoleNotOperatorCreatable { requested_role }` | `handlers/operator::handle_create_session` step 1 | `session create` was invoked with `--role` other than `planner`. Gateway/verifier sessions are minted by kernel-internal spawn paths, not operator IPC. |
| `FAIL_WORKTREE_OUTSIDE_ALLOWED_ROOTS` | `WorktreeOutsideAllowedRoots { worktree_root, allowed_roots }` | `handlers/operator::handle_create_session` step 2 | The `--worktree-root` resolves outside every entry in `policy.toml` `[sessions] allowed_worktree_roots`. |
| `FAIL_BASE_REF_UNRESOLVED` | `BaseRefUnresolved { ref_string, worktree_root, git_stderr }` | `handlers/operator::handle_create_session` step 3 (`git rev-parse <ref>^{commit}`) | The optional `--base-tracking-ref` could not be peeled to a commit OID in the worktree. |
| `FAIL_INVALID_LINEAGE_ID` | `InvalidLineageId { offending_value, parse_error }` | `handlers/operator::handle_create_session` step 2.5 (`Uuid::parse_str(req.lineage_id)`) | The operator supplied a `lineage_id` that does not parse as a UUID v4 hyphenated form (36 ASCII bytes). The CLI ought to have caught this client-side before sending; this code is the kernel's defensive check. |
| `FAIL_SESSION_NOT_FOUND` | `SessionNotFound { session_id }` | `handlers/operator::handle_revoke_session`, `handle_grant_delegation` | The presented `session_id` does not exist in the `sessions` table. |
| `FAIL_SESSION_ALREADY_REVOKED` | `SessionAlreadyRevoked { session_id, revoked_at }` | `authority::session::revoke_session` (`rows_affected == 0` on the conditional `UPDATE`) | Idempotency hit on `session revoke` — the row was already revoked. The desired end state is the same; the CLI nonetheless exits non-zero so orchestration scripts notice. |
| `FAIL_SESSION_INVALID` | `SessionInvalid { session_id, reason }` | `authority::delegation::grant_delegation` step 1 | The session is revoked, expired, or not found. `reason` enumerates which. |
| `FAIL_SESSION_TASK_MISMATCH` | `SessionTaskMismatch { session_id, bound_task, attempted_task }` | `handlers/intent.rs` first-intent admission for sessions created with `--task` | The session was bound to a single task at `session create` time and a subsequent intent's `task_id` does not match. |
| `FAIL_UNKNOWN_CAPABILITY_CLASS` | `UnknownCapabilityClass { offending_value }` | `OperatorRequest::GrantDelegation` deserialiser | `--capability` value does not match any `CapabilityClass` enum variant in `raxis-types`. |
| `FAIL_CAPABILITY_ABOVE_CEILING` | `CapabilityAboveCeiling { role_id, capability_class, ceiling }` | `authority::delegation::grant_delegation` step 2 | The requested `capability_class` is not in the `delegating_role_id`'s ceiling. `ceiling` is returned as a sorted list so the operator immediately sees what the role *can* grant. |
| `FAIL_DELEGATION_TTL_OUT_OF_RANGE` | `DelegationTtlOutOfRange { requested_ttl_seconds, max_ttl_seconds }` | `authority::delegation::grant_delegation` step 3 | `--ttl` is `<= 0` or exceeds `policy.delegations.max_ttl_seconds`. |
| `FAIL_DELEGATION_ALREADY_ACTIVE` | `DelegationAlreadyActive { existing_delegation_id, expires_at }` | `authority::delegation::grant_delegation` step 4 (UNIQUE constraint violation) | A delegation already exists for `(session_id, capability_class)` in `Active` or `StaleOnNextUse` status. v1 has no in-place re-grant — wait for natural expiry. |
| `FAIL_DELEGATION_SIGNATURE_INVALID` | `DelegationSignatureInvalid { proposed_delegation_id, expected_signer }` | `authority::delegation::grant_delegation` step 2.5 (Ed25519 verification of `operator_sig` against the `RAXIS-V1-DELEGATION-GRANT` signing domain — see [`kernel-store.md`](kernel-store.md) §2.5.5 "Delegation grant signing domain on the operator socket") | The operator-supplied `operator_sig` did not verify against the operator's public key over the canonical signing-domain bytes. Most commonly indicates a CLI bug (canonical-bytes serialiser disagreement), a tampered request between CLI and kernel (which the operator UDS file-mode `0600` makes implausible but not impossible), or use of the wrong operator private key. The `expected_signer` is the operator fingerprint that authenticated the connection — the signature was checked against that pubkey. |
| `UNAUTHORIZED` | `OperationNotPermitted { operator_id, attempted_op }` | Every operator IPC dispatcher (per-op `permitted_ops` gate, [`kernel-store.md`](kernel-store.md) §2.5.5 L1424) | The authenticated operator's `permitted_ops` list does not include the requested op. `attempted_op` is the operator IPC variant name (e.g. `"RetryTask"`, `"RotateEpoch"`) so the operator can confirm which entry to add to their policy entry. **Note:** the bare wire string `UNAUTHORIZED` is shared with the *planner* socket's `PlannerErrorCode::UNAUTHORIZED` variant (planner-facing table above), but the two enums live in different Rust types (`OperatorErrorCode` vs `PlannerErrorCode`) and carry different `detail` shapes — the socket the message arrived on disambiguates which decoder to use. |

Adding a new operator error code requires adding both a new `OperatorErrorCode` enum value and a matching `OperatorErrorDetail` variant in the same PR — the spec disallows codes whose `detail` shape is undefined.

Normative operator CLI behaviour and the full per-command IPC discriminant table are in [`cli-ceremony.md`](cli-ceremony.md).

### Budget awareness

After each `Accepted` response, the planner reads `remaining_budget` and compares to its internal cost estimate for the next planned intent. If the estimate exceeds the remaining budget, the planner should:
1. Complete the current work and submit `CompleteTask` if the task is otherwise done.
2. If more work is needed: submit `ReportFailure` with a justification citing budget exhaustion, so the operator can review and re-budget.

The planner must not attempt to game the budget by under-declaring scope in its next intent — `estimated_cost` is kernel-computed (INV-02A).

### Session token handling

- The session token is a kernel-issued credential. The planner stores it in memory and presents it on every `IntentRequest`.
- If the kernel returns `UNAUTHORIZED`, the token is invalid. The planner must **not** retry with the same token or attempt to obtain a new token through the planner IPC path (token issuance is a kernel-internal operation at session creation).
- Token rotation in v1 is not supported. If a token expires or is revoked, the session ends.

---

### `EscalationRequest` wire shape (planner → kernel)

The planner submits an `EscalationRequest` on the **planner UDS** (`<data_dir>/sockets/planner.sock`) — the same socket as `IntentRequest`. It is a top-level `IpcMessage::EscalationRequest(EscalationRequest)` variant; verifier sessions attempting to send it are rejected at the dispatcher ([`kernel-core.md`](kernel-core.md) Part 2.3 §`ipc/dispatch.rs`) before reaching the handler. The full handler contract is [`kernel-core.md`](kernel-core.md) Part 2.3 §`src/ipc/handlers/escalation.rs`; the wire shape and response envelope below are the planner-facing surface.

> **Encoding reminder:** Illustrative JSON projection of `IpcMessage::EscalationRequest { .. }` in `raxis-ipc`. On-wire: length-prefixed bincode-2 frame per `raxis-ipc::frame`.

```json
{
  "session_token":    "<64-char hex; same shape as IntentRequest.session_token>",
  "task_id":          "<uuid v4>",
  "class":            "CapabilityUpgrade",
  "requested_scope": {
    "kind":           "CapabilityUpgrade",
    "capability":     "WriteSecrets"
  },
  "justification":    "<free text, max 4096 chars; required and non-empty>",
  "idempotency_key":  "<uuid v4>"
}
```

**Fields (the corresponding Rust struct lives in `raxis-types/src/escalation.rs`; field names below match the Rust struct verbatim — JSON tags are the same):**

- `session_token` (`String`, required) — the kernel-issued session credential, identical to `IntentRequest.session_token` (64-char lowercase hex). The planner socket has no per-connection auth state, so every frame carries its own credential. The kernel resolves it via `authority::session::get_session_by_token` to recover `session_id`, `lineage_id`, and (via `task_id`) `initiative_id`, all of which are needed to populate the `escalations` row. Unknown / revoked / expired tokens produce `EscalationResponse::Rejected`.
- `task_id` (`TaskId`, required) — the task this escalation applies to. The kernel rejects with `HandlerError::InvalidTask` if the task does not exist; with `HandlerError::Unauthorized` if `task.session_id != session.session_id` (planners cannot escalate on behalf of another session's task).
- `class` (`EscalationClass`, required) — one of `CapabilityUpgrade` | `DelegationRenewal` | `BudgetException` | `QualityGateException` | `MergeConflict` | `LogicalDeadlock` (full enum in `raxis-types/src/escalation.rs`; canonical reference in [`philosophy.md`](philosophy.md) §`src/escalation.rs`). Determines which `requested_scope` variant is valid; mismatches are rejected at the deserialiser (serde-tagged enum). `LogicalDeadlock` is kernel-initiated only (`INV-ESCALATION-AUTO-LOGICAL-DEADLOCK-01`) and MUST be rejected at planner-side admission; it is materialised by the kernel directly via `orch_respawn_ceiling::insert_logical_deadlock_escalation_in_tx` paired with `OrchestratorRespawnCeilingExceeded`.
- `requested_scope` (`RequestedEscalationScope`, required) — serde-tagged enum where `kind` matches `class`. The four variant shapes:
  - `CapabilityUpgrade { capability: CapabilityClass }`
  - `DelegationRenewal { delegation_id: DelegationId }`
  - `BudgetException { additional_units: u64 }`
  - `QualityGateException { gate_type: GateType, task_id: TaskId }` — the inner `task_id` MUST equal the outer `task_id`; mismatch is rejected at the handler (`HandlerError::InconsistentScope`).
- `justification` (`String`, required, non-empty, max 4096 chars) — opaque to kernel policy; logged verbatim into the audit chain so the operator sees the planner's stated reason. Empty or oversized → `HandlerError::InvalidJustification`.
- `idempotency_key` (`Uuid`, required) — planner-supplied UUID v4. The kernel uses it to deduplicate retried submissions: if a `Pending` or `Approved` escalation row already exists for `(session_id, task_id, class, idempotency_key)`, the kernel returns `EscalationResponse::AlreadyPending { escalation_id }` for that prior row instead of creating a duplicate. The planner SHOULD generate a fresh UUID for each new submission and reuse the same one across retries of that submission.

The kernel-assigned fields (`escalation_id`, `lineage_id`, `initiative_id`, `submitted_at`, `timeout_at`, `status`) are **not** present in the request; they are populated by `handlers/escalation.rs` step 4 and surfaced in the response below.

### `EscalationResponse` wire shape (kernel → planner)

```json
{
  "kind": "Submitted",
  "escalation_id": "<uuid v4>",
  "timeout_at":    1714596523
}
```

**Variants (`EscalationResponse` in `raxis-types/src/escalation.rs`):**

| Variant | Fields | Meaning |
|---|---|---|
| `Submitted` | `escalation_id: EscalationId`, `timeout_at: UnixSeconds` | Escalation row was created (`status: Pending`). The planner MUST persist `escalation_id` (in its own state) — it is the handle the planner later presents on the next `IntentRequest`'s `approval_token` field once the operator has approved (the operator-issued `ApprovalToken.escalation_id` will match). `timeout_at` is the absolute Unix timestamp at which the escalation auto-transitions to `TimedOut` if the operator does not act. |
| `AlreadyPending` | `escalation_id: EscalationId` | An escalation with the same `(session_id, task_id, class, idempotency_key)` is already `Pending` or `Approved`. Returned in lieu of creating a duplicate row. The `escalation_id` is the existing one — the planner can reuse it as if a fresh `Submitted` had been returned. No `timeout_at` because the original submission's `timeout_at` is what governs (and the planner can re-query via a future `escalation status` IPC, deferred to v2). |
| `Rejected` | `reason: EscalationErrorCode` | The escalation is well-formed but the kernel refuses to record it. The two v1 reasons are `RateLimitExceeded` (the per-lineage submission counter exceeded `policy.escalation_max_per_window`) and `LineageQuarantined` (the lineage has been quarantined by exceeding `policy.escalation_quarantine_threshold` cumulative rate-limit hits — only an operator `raxis-cli quarantine lift` clears this). Distinct from transport-level errors (malformed payload, unauthorized session, invalid task), which surface as `IpcResponse::Error(PlannerErrorCode::*)` instead. |

**`EscalationErrorCode` (wire enum):**

| Variant | Wire string | Planner action |
|---|---|---|
| `RateLimitExceeded` | `"RateLimitExceeded"` | Wait until the current window expires (`policy.escalation_window` seconds; default 3600 = 1h) before resubmitting. Persistent rate-limiting will eventually trip quarantine. |
| `LineageQuarantined` | `"LineageQuarantined"` | Stop submitting escalations on this lineage. The operator must lift the quarantine via `raxis-cli quarantine lift <lineage_id>`. The planner SHOULD `IntentKind::ReportFailure` on the affected task with a justification explaining the quarantine condition. |

### Presenting the approval token on the next intent

Once the operator runs `raxis-cli escalation approve`, the planner is notified out-of-band. v1's default routing (per [`cli-readonly.md`](cli-readonly.md) §5.6) writes an `EscalationApproved` notification to the Shell channel (`<data_dir>/notifications/inbox.jsonl`); operator tooling that watches that file (e.g. a `raxis inbox -f` sidecar, or a custom scriptlet that tails the JSONL) is responsible for prodding the planner. The kernel itself does not push to the planner over IPC in v1. When the planner is ready to retry the gated action, it submits the next `IntentRequest` with the `approval_token` field populated:

```json
{
  "task_id":         "<uuid>",
  "intent_kind":     "SingleCommit",
  "base_sha":        "...",
  "head_sha":        "...",
  "approval_token": {
    "approval_id":   "<uuid from ApprovalToken>",
    "escalation_id": "<uuid from EscalationResponse::Submitted>",
    "operator_sig":  "<64-byte hex Ed25519>"
  }
}
```

The `escalation_id` in the presented token MUST match the `escalation_id` returned by the original `EscalationResponse::Submitted` (or `AlreadyPending`). Mismatch → `IntentResponse::Rejected { reason: FAIL_APPROVAL_TOKEN_INVALID }`. The full eight-step `validate_approval_token` flow runs at intent admission ([`kernel-core.md`](kernel-core.md) Part 2.3 §`authority/approval.rs`); the planner does not need to model the full validation locally — it just presents the token and reads the `IntentResponse`.

**Audit visibility.** Every escalation submission produces `AuditEventKind::EscalationSubmitted { escalation_id, session_id, task_id, class, requested_scope_summary }` (see [`kernel-core.md`](kernel-core.md) Part 2.3 §`handlers/escalation.rs` step 5). Rate-limit and quarantine outcomes produce their own audit events (`EscalationRateLimitExceeded`, `LineageQuarantined`). The planner cannot read the audit chain — but the operator can, which is the intended forensic surface.

---

## §3.2 — Gateway Wire Format

### What the gateway is

The gateway is a subprocess spawned by the kernel at startup. It holds provider API credentials (loaded from `<data_dir>/providers/`) and proxies all external provider calls on the kernel's behalf. The planner has no direct path to provider APIs (INV-02A, INV-02B).

The gateway communicates with the kernel exclusively over the gateway UDS (`<data_dir>/sockets/gateway.sock`). It authenticates using a `gateway_process_token` issued at spawn time (distinct from planner session tokens).

**Inference path:** When the kernel needs to make a model inference call, it constructs the provider-specific request body (via `provider/` adapter) and sends it to the gateway as a `FetchRequest` with `fetch_kind: "Inference"`. The gateway is not aware of the semantic content of the request — it proxies bytes and injects credentials. `InferenceRequest` in [`kernel-core.md`](kernel-core.md) refers to the kernel-internal abstraction; `FetchRequest` here is the kernel→gateway wire message. There is no separate `InferenceRequest` on the gateway UDS — all external calls are `FetchRequest`.

### Spawn model

```text
kernel main.rs step 9 →
    spawn_gateway(gateway_binary_path, gateway_process_token, gateway_socket_path, data_dir)
        → env: RAXIS_GATEWAY_TOKEN=<64-char hex>, RAXIS_GATEWAY_SOCKET=<absolute path>,
                RAXIS_DATA_DIR=<absolute path>, RAXIS_GATEWAY_BACKEND={mock|http}
        → gateway loads <data_dir>/policy/policy.toml + per-provider credentials
        → gateway connects to gateway.sock, sends GatewayMessage::GatewayReady { gateway_token }
        → kernel records gateway as ready (Phase A.5 supervisor)
```

**Single-subprocess model.** The kernel spawns exactly **one** `raxis-gateway` subprocess. There is no pool. Tokio gives the gateway all the concurrency it needs — one task per in-flight `FetchRequest`. Even with 50+ concurrent planners issuing inference calls, the kernel multiplexes them all over the single `gateway.sock` and the gateway fans them out to the upstream APIs as concurrent async futures. There is zero architectural benefit to a pool on a single host.

**Crash-and-respawn.** If the gateway panics, segfaults, or is killed by the OS (OOM), the kernel detects the closed `gateway.sock` connection and respawns it with a brand-new `gateway_process_token` (random 32 bytes). The token is in-memory only — never persisted. In-flight `FetchRequest` UUIDs whose response was lost in the crash window are returned to their planner callers as `error: "GatewayUnavailable"` (the kernel-side `gateway::*` adapter handles the bookkeeping, Phase A.5).

**v1 backend constraint.** The `RAXIS_GATEWAY_BACKEND` env var selects the outbound HTTP impl. v1 ships with `mock` (canned responses, used by tests + offline development). `http` (real `reqwest`-based outbound calls) is reserved and lands in a follow-up PR; until then a gateway started with `RAXIS_GATEWAY_BACKEND=http` falls back to `mock` with a one-line warning so operators get visible feedback.

**Provider-for-host derivation (v1).** The current `FetchRequest` wire shape carries no `provider_id`; the gateway derives the provider by URL hostname:
- `kind = "Anthropic"` matches any host ending in `anthropic.com`.
- `kind = "OpenAI"`    matches any host ending in `openai.com`.
- All other kinds: no auto-match → `error: "UnknownProviderForHost"`.

v2 will add an explicit `url_match` field per `[[providers]]` entry to make the binding declarative; until then operators wanting third-party providers MUST use one of the two known kinds OR run a fork. This rule is implemented in `gateway/src/dispatch.rs::provider_for_host` and pinned by the `dispatch::tests` module.

### `FetchRequest` wire shape (kernel → gateway)

> **Encoding reminder:** Illustrative JSON projection of `GatewayMessage::FetchRequest { .. }` in `raxis-ipc`. On-wire: length-prefixed frame per `raxis-ipc::frame`.

```json
{
  "gateway_token":  "<hex>",
  "fetch_id":       "<uuid-v4>",
  "fetch_kind":     "Inference",
  "url":            "https://api.anthropic.com/v1/messages",
  "method":         "POST",
  "headers":        { "Content-Type": "application/json" },
  "body_bytes":     "<base64-encoded request body>",
  "timeout_ms":     30000,
  "session_id":     "<uuid>",
  "task_id":        "<task-id or null>"
}
```

- `fetch_kind` — `"Inference"` (LLM API call) or `"DataFetch"` (URL fetch for context). The gateway applies different timeout and size limits per kind.
- `url` — pre-validated by the kernel against the domain allowlist before being sent to the gateway. The gateway **re-validates** against its own copy of the allowlist — defence in depth (see §Domain allowlist re-validation).
- `timeout_ms` — kernel-specified; gateway enforces. Maximum 120000 ms (v1).

### `FetchResponse` wire shape (gateway → kernel)

> **Encoding reminder:** Illustrative JSON projection of `GatewayMessage::FetchResponse { .. }` in `raxis-ipc`.

```json
{
  "fetch_id":       "<uuid-v4>",
  "status_code":    200,
  "headers":        { "Content-Type": "application/json" },
  "body_bytes":     "<base64-encoded response body>",
  "latency_ms":     842,
  "error":          null
}
```

Or on error:

```json
{
  "fetch_id":   "<uuid-v4>",
  "status_code": null,
  "headers":     null,
  "body_bytes":  null,
  "latency_ms":  30000,
  "error":       "TimeoutExceeded"
}
```

**v1 constraint:** Full-response buffering only. The gateway buffers the entire response body before returning `FetchResponse`. No streaming. Maximum response body size: 16 MiB (configurable in `[[providers]]` policy block). Bodies exceeding the limit → `error: "ResponseTooLarge"`.

### Domain allowlist re-validation

Before forwarding any request, the gateway resolves the `url`'s hostname and checks it against the domain allowlist. The gateway loads the allowlist from the policy artifact at startup (`<data_dir>/policy/policy.toml`). It does **not** receive an allowlist from the kernel via IPC — it reads the file directly. On epoch advance, the kernel signals the gateway via a `GatewayMessage::EpochAdvanced { new_epoch_id }` message; the gateway re-reads `policy.toml` and reloads the allowlist before processing the next request. If the re-read fails, the gateway returns `error: "PolicyReloadFailed"` on all subsequent requests until the next successful reload — failure-closed on mismatch. If the hostname is not in the allowlist → gateway returns `error: "DomainNotAllowed"` without making any external request. This re-validation is **independent** of the kernel's pre-validation — the gateway does not trust the kernel's pre-validation result.

### Provider credential storage

Provider credentials (API keys) are stored in `<data_dir>/providers/<provider_name>.toml`, readable only by the kernel OS user. The gateway loads them at startup. The kernel never reads provider credentials directly — it sends the request body to the gateway, which injects the credential header before forwarding.

### `[gateway]` and `[[providers]]` policy schema (NORMATIVE)

Both sections are **OPTIONAL**: a kernel started against a policy artifact with neither boots cleanly and serves operator IPC, but no `FetchRequest` can be dispatched (audit-only / no-LLM deployment). Operators who run a model workflow add both sections at epoch 1 (genesis policy template ships them as commented blocks in `crates/genesis-tools/src/policy_toml.rs`).

```toml
[gateway]
binary_path              = "/usr/local/bin/raxis-gateway"   # MUST be absolute
spawn_timeout_secs       = 5     # default; max 60
respawn_backoff_ms       = 1000  # initial; doubles each consecutive crash, cap 60_000
max_consecutive_respawns = 5     # circuit-breaker; quarantines after this many crashes

[[providers]]
provider_id           = "anthropic-prod"  # unique within the array
kind                  = "Anthropic"       # known: "Anthropic", "OpenAI"; unknown accepted (forward-compat) but rejected at dispatch
credentials_file      = "anthropic-prod.toml"   # bare filename, resolved under <data_dir>/providers/
inference_timeout_ms  = 30000   # default; max 120000 (peripherals.md §3.2)
data_fetch_timeout_ms = 10000   # default; max 60000
max_response_bytes    = 16777216 # default 16 MiB; max 64 MiB
```

`PolicyBundle::validate` (in `crates/policy/src/bundle.rs`) enforces the following — fail-closed at policy load time, before the kernel binds any sockets:

- `[gateway].binary_path` MUST be absolute. Relative paths are rejected to prevent PATH-based hijacks. The file's existence is checked at *spawn* time (not validate time) since policy.toml may travel separately from the binary.
- `[gateway].spawn_timeout_secs`, `respawn_backoff_ms`, and `max_consecutive_respawns` MUST all be `> 0`. Zero `max_consecutive_respawns` is rejected with a hint that `1` (not `0`) disables auto-respawn.
- Every `[[providers]] provider_id` is non-empty and unique within the array.
- Every `credentials_file` is a bare filename — no `/`, no `\`, no `.`, no `..`. The validator rejects path-traversal payloads at policy load time, *before* the gateway opens the file.
- Each timeout / size knob is `> 0` and `<=` the spec ceiling (`MAX_INFERENCE_TIMEOUT_MS = 120_000`, `MAX_DATA_FETCH_TIMEOUT_MS = 60_000`, `MAX_RESPONSE_BYTES_CEILING = 64 MiB`).

The bootstrap ceremony (`kernel/src/bootstrap.rs::run_inner`) creates `<data_dir>/providers/` with mode `0700` so the operator can drop a credentials file in immediately after first boot.

These rules are pinned by the `gateway_providers_tests` test module in `crates/policy/src/bundle.rs` (15 tests covering happy path, defaults, and every fail-closed branch) plus `bootstrap::edge_cases::bootstrap_creates_providers_directory_with_0700_permissions`.

---

## §3.3 — Verifier Subprocess Contract

### What the verifier is

The verifier is a short-lived subprocess spawned by `src/gates/verifier_runner.rs` to evaluate one gate for one task. It is **not** a persistent service — it runs, submits one `WitnessSubmission`, and exits.

The verifier binary is operator-provided (configured in `[[gates]]` as `verifier_command`). RAXIS does not ship verifier binaries — operators write or install them. The contract this section defines is the interface that every verifier binary must implement.

### Input: `VerifierSpawnEnvelope`

All input arrives via environment variables. See [`kernel-store.md`](kernel-store.md) §2.5.6 for the normative env var table. Summary:

| Env var | Purpose |
|---|---|
| `RAXIS_VERIFIER_TOKEN` | Auth token to present when submitting witness |
| `RAXIS_TASK_ID` | Task being evaluated |
| `RAXIS_EVALUATION_SHA` | Commit OID the evaluation is bound to |
| `RAXIS_WORKTREE_ROOT` | Working directory for evaluation |
| `RAXIS_KERNEL_SOCKET` | UDS socket to submit witness to |
| `RAXIS_GATE_TYPE` | Gate type being evaluated |
| `RAXIS_INITIATIVE_ID` | Initiative context (logging only) |

The verifier must not rely on any other env vars. The kernel clears the environment before exec.

### Output: `WitnessSubmission`

The verifier submits exactly one `WitnessSubmission` to `RAXIS_KERNEL_SOCKET` before exiting:

> **Encoding reminder:** Illustrative JSON projection of `IpcMessage::WitnessSubmission { .. }` in `raxis-ipc`. On-wire: length-prefixed frame per `raxis-ipc::frame`.

```json
{
  "verifier_token":   "<RAXIS_VERIFIER_TOKEN value>",
  "task_id":          "<RAXIS_TASK_ID value>",
  "gate_type":        "<RAXIS_GATE_TYPE value>",
  "evaluation_sha":   "<RAXIS_EVALUATION_SHA value>",
  "result_class":     "Pass",
  "body":             { ... }
}
```

**`result_class` — canonical enum (`WitnessResultClass` in `raxis-types/src/witness.rs`):**

The wire-string values MUST match the SQLite `CHECK` constraint on `witness_records.result_class` ([`kernel-store.md`](kernel-store.md) §2.5.1 Table 13: `CHECK (result_class IN ('Pass', 'Fail', 'Inconclusive'))`). The DDL is the authority on the variant names per the supersession rule in [`kernel-store.md`](kernel-store.md) §2.5.1; the wire enum has been aligned to match.

| Variant | Meaning |
|---|---|
| `Pass` | Gate evaluation ran and evidence meets the policy threshold. |
| `Fail` | Gate evaluation ran but evidence does not meet threshold (e.g. coverage below minimum, test failures, build broken). Gate outcome is `Fail` — recorded permanently in `witness_records` and surfaced to the planner as `FAIL_INSUFFICIENT_WITNESS` on subsequent intents. |
| `Inconclusive` | Verifier could not complete evaluation due to an environmental error (build toolchain missing, test runner segfault, network outage during a test that legitimately requires network). Distinct from `Fail`: the verifier did not get a clean read on the evidence. The kernel re-queues for retry up to `max_verifier_retries` (default 2, configured in `policy.toml` `[verifier]` block); if every retry returns `Inconclusive`, the gate cannot clear and the task is marked `Aborted` with `BlockReason::WitnessTimeout` (re-using the existing taxonomy — operator investigates the verifier environment). **Note on naming**: older drafts called this variant `Error`; that name was non-canonical and conflicted with the DDL. The canonical wire string is `Inconclusive`. |

These are the **only** valid `result_class` values in v1. Any other value → witness rejected, `verifier_run_token` consumed (treat as malformed submission).

- `body` — gate-type-specific structured evidence. Schema is defined per `GateType` in `raxis-types/src/witness.rs`. The kernel validates the body schema; malformed bodies → witness rejected, verifier token consumed.
  - **Wire encoding contract:** the in-memory shape is `serde_json::Value`, but on the bincode wire the field is encoded as a **JSON string** (length-prefixed UTF-8) via the `json_value_as_string` serde helper in `raxis-types::witness`. This is required because `serde_json::Value::deserialize` dispatches via `serde::Deserializer::deserialize_any`, which the bincode (non-self-describing) codec refuses with `Decode(Serde(AnyNotSupported))`. Without the helper, ANY non-trivial witness body would fail to round-trip; the helper makes the body opaque-to-bincode but transparent-to-callers (the public field type stays `serde_json::Value`). Pinned by `raxis_types::witness::tests::witness_submission_round_trips_through_bincode` and the full IPC loopback test in `kernel/src/gates/verifier_runner.rs::stub_round_trip::*`.
- `evaluation_sha` — must match `RAXIS_EVALUATION_SHA`. Mismatch → `EvaluationShaMismatch`; token not consumed; verifier effectively failed without submitting.

### Idempotency and dedup key

The kernel deduplicates witness submissions on `(task_id, gate_type, verifier_run_token)` — the composite unique key for a verifier run, matching the `verifier_run_tokens` table (§2.5.1 Table 12). `evaluation_sha` is not part of the dedup key because the token is already bound to a specific `(task_id, evaluation_sha)` at spawn time (any mismatch is rejected before dedup check). A second submission with the same token on the same connection is rejected. A re-spawned verifier receives a new token and is a new independent run.

### Exit codes

| Exit code | Meaning |
|---|---|
| `0` | Submission was sent (outcome determined by `result_class`, not exit code) |
| Non-zero | Subprocess failure before submission — kernel treats as verifier process failure, not a gate outcome |

### Determinism requirement

For a given `(task_id, evaluation_sha, gate_type)` triple, the verifier **must** produce the same `result_class` and a structurally equivalent `body` on every invocation, given the same worktree state. This is required because:
1. The kernel may re-spawn the verifier on process failure.
2. `recovery::reconcile` may re-check witness records.
3. Non-determinism here means gate outcomes are unreproducible — violating INV-05.

Verifiers that have inherent non-determinism (e.g. network-dependent tests) must implement their own determinism wrapper (caching, retry-with-timeout, etc.).
