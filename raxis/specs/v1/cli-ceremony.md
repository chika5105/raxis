# RAXIS — Part 4: CLI, Genesis Ceremony, and Fixtures

> **Scope:** `raxis` subcommands and their normative behaviour (§4.1), the genesis key ceremony step-by-step (§4.2), and the canonical integration test fixtures with their v1 test matrix cross-references (§4.3).
>
> **Navigation:** [README](../../README.md) | [Part 2 Store](kernel-store.md) | [Part 3](peripherals.md) | [Planner API](planner-api.md)
>
> **Authority:** Where this file and `kernel-store.md` conflict on key file names, formats, or paths, `kernel-store.md` §2.5.4 wins. Where this file describes CLI subcommand behaviour that drives the operator auth protocol, `kernel-store.md` §2.5.5 wins on the wire format.
>
> **Binary vs crate name.** The user-facing operator binary is **`raxis`**. The Cargo crate that produces it is `raxis-cli` (kept stable so workspace dependencies do not have to churn). Earlier drafts of this spec used `raxis-cli` everywhere; treat any remaining `raxis-cli <subcommand>` example below as equivalent to `raxis <subcommand>` — the binary on disk and on `$PATH` is `raxis`.

---

## §4.1 — `raxis` Subcommands

`raxis` is the operator-facing binary. All operator interactions with the kernel go through this tool. It communicates exclusively over the operator UDS (`<data_dir>/sockets/operator.sock`), performing the challenge-response handshake on every invocation.

### Global flags

```
raxis [--data-dir <path>] [--socket <path>] <subcommand>
```

| Flag | Default | Description |
|---|---|---|
| `--data-dir` | `~/.raxis` | Kernel data directory. All relative paths are resolved from here. |
| `--socket` | `<data_dir>/sockets/operator.sock` | Override operator socket path. |

All subcommands that require kernel connectivity will fail with `ERR_SOCKET_NOT_FOUND` if the operator socket does not exist (kernel not running).

---

### `genesis`

**Purpose:** Run the initial key generation ceremony. Generates all four key families and writes the initial `policy.toml`. Must be run before the kernel is started for the first time.

**Usage:** `raxis-cli genesis [--operator-pubkey <path>] [--force]`

**Behaviour:**
1. Checks that `<data_dir>/keys/` does not already contain key files. Exits with `ERR_ALREADY_INITIALIZED` if it does (prevents accidental re-genesis). Use `--force` only with explicit intent to destroy existing keys.
2. Generates `authority_keypair` (Ed25519) → writes `<data_dir>/keys/authority_keypair.pem`.
3. Generates `quality_keypair` (Ed25519) → writes `<data_dir>/keys/quality_keypair.pem`.
4. Generates `verifier_token_key` (32 CSPRNG bytes) → writes `<data_dir>/keys/verifier_token_key.bin`.
5. Operator public key handling:
   - If `--operator-pubkey <path>` is provided: reads the Ed25519 public key from that path, computes fingerprint, writes `<data_dir>/keys/operator_<fingerprint>.pub`.
   - If not provided: prompts the operator to paste their Ed25519 public key (hex or PEM). The kernel never sees the operator's private key.
6. Writes initial `policy.toml` to `<data_dir>/policy/policy.toml` with:
   - `authority_pubkey` = public key extracted from `authority_keypair.pem`
   - `quality_pubkey` = public key extracted from `quality_keypair.pem`
   - `[[operators.entries]]` = the registered operator entry with `permitted_ops = ["CreateInitiative", "ApprovePlan", "RejectPlan", "CreateSession", "RevokeSession", "GrantDelegation", "RetryTask", "ResumeTask", "AbortTask", "AbortInitiative", "ApproveEscalation", "DenyEscalation", "RotateEpoch"]` (the canonical 13-operation v1 set per `kernel-store.md` §2.5.5 IPC discriminant table — omit keys only if you intentionally deny that capability)
   - Empty `[[tasks]]`, `[[gates]]`, and `[[tools]]` sections
7. Prompts the operator to sign `policy.toml` with their private key using `raxis-cli policy sign` and store `policy.sig` alongside it. The ceremony is not complete until `policy.sig` exists.
8. Prints a summary of generated files and next steps.

**Files written:**
- `<data_dir>/keys/authority_keypair.pem`
- `<data_dir>/keys/quality_keypair.pem`
- `<data_dir>/keys/verifier_token_key.bin`
- `<data_dir>/keys/operator_<fingerprint>.pub`
- `<data_dir>/policy/policy.toml`

**Does not start the kernel.** The operator starts the kernel separately after ceremony completion.

---

### `genesis --rotate <key-family>`

**Purpose:** Key rotation ceremony for a single key family. Safe to run while kernel is stopped.

**Usage:** `raxis-cli genesis --rotate [authority | quality | verifier-token | operator]`

**Behaviour:**
- Stops cleanly if the kernel is detected as running (checks for active socket).
- Generates new key material for the specified family.
- For `operator`: prompts for new public key; removes old `.pub` file; writes new one; operator must re-sign all active plan artifacts with the new key.
- For any key: prints "You must advance the policy epoch before resuming work. After restarting the kernel, stage the new signed policy artifact under `<data_dir>/policy/` and run: `raxis-cli epoch advance --policy <path> --sig <path>` (both arguments required; see the `epoch advance` section below)."
- Does **not** automatically advance the epoch — that is a separate explicit step requiring the operator to stage the new signed artifact and pass its paths.

---

### `policy sign`

**Purpose:** Sign a policy or plan artifact with the operator's private key.

**Usage:** `raxis-cli policy sign <artifact.toml> --key <operator_private_key_path>`

**Behaviour:**
1. Reads `<artifact.toml>` bytes verbatim.
2. Computes `SHA-256(file_bytes)`.
3. Signs the SHA-256 digest with the operator's Ed25519 private key.
4. Writes `<artifact>.sig` (same directory as `<artifact.toml>`) in the TOML format defined in §2.5.3.
5. Prints the fingerprint and plan_sha256 for verification.

**Note:** The operator's private key is read locally and is never sent to the kernel. `raxis-cli policy sign` does not open the operator socket.

---

### `plan submit`

**Purpose:** Submit a signed plan to the kernel to create a new initiative.

**Usage:** `raxis-cli plan submit <initiative_id> <plan_dir>`

`<plan_dir>` must contain both `plan.toml` and `plan.sig`.

**Behaviour:**
1. Opens operator socket; performs challenge-response handshake.
2. Sends `CreateInitiative { initiative_id, plan_toml_path, plan_sig_path }`.
3. Kernel verifies signature and creates the initiative row.
4. On success: prints `Initiative <initiative_id> created. Status: Draft`.
5. On `FAIL_UNKNOWN_SIGNER`: prints the fingerprint from `plan.sig` and instructs the operator to register the key with `raxis-cli operator add-key`.
6. On `FAIL_INITIATIVE_EXISTS`: prints existing status; does not overwrite.

---

### `plan approve`

**Purpose:** Approve a draft initiative, transitioning it from `Draft → ApprovedPlan` and scheduling tasks for execution.

**Usage:** `raxis-cli plan approve <initiative_id>`

**Behaviour:**
1. Opens operator socket; performs challenge-response handshake.
2. Sends `ApprovePlan { initiative_id }`.
3. Kernel transitions state and schedules all ready tasks (those with no predecessors).
4. On success: prints initiative status and list of tasks now queued.
5. Requires `ApprovePlan ∈ permitted_ops` for the authenticated operator.

---

### `plan reject`

**Purpose:** Abandon a draft initiative without instantiating tasks.

**Usage:** `raxis-cli plan reject <initiative_id>`

**Behaviour:**
1. Opens operator socket; performs challenge-response handshake.
2. Sends `RejectPlan { initiative_id }`.
3. Kernel calls `lifecycle::reject_plan` — requires initiative `Draft`; transitions initiative to `Aborted`.
4. Requires `RejectPlan ∈ permitted_ops`.

---

### `initiative abort`

**Purpose:** Force-terminate an active initiative and bulk-cancel all non-terminal tasks (`lifecycle::abort_initiative`).

**Usage:** `raxis-cli initiative abort <initiative_id>`

**Behaviour:**
1. Opens operator socket; performs challenge-response handshake.
2. Sends `AbortInitiative { initiative_id }`.
3. Kernel bulk-cancels tasks per store spec; initiative → `Aborted`.
4. Requires `AbortInitiative ∈ permitted_ops`.

---

### `escalation approve`

**Purpose:** Approve a pending escalation, issuing an `approval_token` for the planner.

**Usage:** `raxis-cli escalation approve <escalation_id> --scope <capability_class> --max-uses <n> --valid-for <seconds>`

**Behaviour:**
1. Opens operator socket; performs challenge-response handshake.
2. Constructs `approval_scope = { capability_class, max_uses, valid_for_seconds }`.
3. Signs `(escalation_id || approval_scope_canonical_bytes)` with operator's private key → `operator_sig`.
4. Sends `ApproveEscalation { op_token, escalation_id, approval_scope, operator_sig }`.
5. Kernel writes `approval_tokens` + `approval_proofs` rows.
6. On success: prints the `approval_token` value. Operator passes this to the planner out-of-band (e.g. via the plan or a side channel).
7. Requires `ApproveEscalation ∈ permitted_ops`.

---

### `escalation deny`

**Purpose:** Deny a pending escalation. The planner receives no approval token; the escalation transitions `Pending → Denied`. The task remains in whatever state it was in when the escalation was submitted — the operator must follow up with `task abort` or `task retry` depending on intent.

**Usage:** `raxis-cli escalation deny <escalation_id> [--reason <text>]`

**Wire format (operator → kernel):**

```
Operator → Kernel: DenyEscalation {
  op_token:       "<operator session token>",
  escalation_id:  "<uuid>",
  reason:         "<optional free text, max 512 chars; stored in audit only>"
}
```

**Behaviour:**
1. Opens operator socket; performs challenge-response handshake.
2. Sends `DenyEscalation { op_token, escalation_id, reason }`.
3. Kernel validates: `escalation.status == Pending`. Any other status → `FAIL_ESCALATION_NOT_PENDING { current_status }`.
4. Kernel transitions escalation `Pending → Denied`; emits `AuditEventKind::EscalationDenied { escalation_id, denied_by: operator_id, reason }`.
5. Kernel does **not** issue any token or notify the planner automatically — the planner will time out waiting for approval and receive `EscalationTimedOut` semantics on next check. Operator decides next step for the task independently.
6. Requires `DenyEscalation ∈ permitted_ops`.

**Note:** `DenyEscalation` does not carry an `operator_sig` over escalation scope (unlike `ApproveEscalation`) — denial creates no durable approval artifact. The denial is recorded in the audit log only. INV-ESC-01 is not implicated: denial does not involve token issuance.

---

### `task abort`

**Purpose:** Abort a running task immediately.

**Usage:** `raxis-cli task abort <task_id>`

**Behaviour:**
1. Opens operator socket; performs challenge-response handshake.
2. Sends `AbortTask { task_id }`.
3. Kernel transitions task to `Aborted` with `BlockReason::OperatorAbort`, records audit event.
4. On success: prints new task status.
5. Requires `AbortTask ∈ permitted_ops`.

---

### `task resume`

**Purpose:** Resume a `BlockedRecoveryPending` task after a kernel crash recovery. Transitions the task from `BlockedRecoveryPending → Running` so the planner session that was interrupted can continue (or a new session can be attached). This is the **recovery resume** operation.

INV-INIT-05: the planner cannot self-resume a `BlockedRecoveryPending` task. Only operator CLI can trigger this transition.

**Usage:** `raxis-cli task resume <task_id>`

**Behaviour:**
1. Opens operator socket; performs challenge-response handshake.
2. Sends `OperatorRequest::ResumeTask { task_id }` (operator IPC variant).
3. Kernel calls `recovery::resume_task(task_id, operator_id)` — validates `task.state == TaskState::BlockedRecoveryPending`. Any other state → `OperatorResponse::Error { code: FAIL_TASK_NOT_RESUMABLE, detail: TaskNotResumable { current_state } }` per the operator-error envelope normatively defined in `peripherals.md` §3 "Operator socket". The CLI deserialises `detail` and renders `"Cannot resume: task is in state <current_state> (must be BlockedRecoveryPending)"` to stderr; exit code is non-zero.
4. On success, kernel transitions task `BlockedRecoveryPending → Running`; emits `AuditEventKind::TaskResumed`; returns `OperatorResponse::TaskResumed { task_id, prior_state, transitioned_at }` (`prior_state` echoed from the `TaskNeedsRecovery` audit event so the operator sees what was interrupted).
5. Requires `ResumeTask ∈ permitted_ops`.

**Note:** After `task resume`, the operator must attach a planner session to the task to continue work. The kernel does not automatically reconnect the prior session (it may have been terminated at crash time).

**Gate-progress preservation across recovery (per INV-INIT-08, `kernel-core.md` §4.4):** `task resume` always lands the task in `Running` regardless of its `prior_state` (`Admitted` / `GatesPending` / `Running` at crash time — visible in the `TaskNeedsRecovery { prior_state, … }` audit event written during `recovery::reconcile_tasks`). Pre-crash gate progress is not lost: `witness_records` (Table 13) preserves every accepted witness across restarts, and the next `IntentRequest` from the attached planner session re-runs `evaluate_claims` against those records. Witnesses that arrived before the crash satisfy their gates without re-execution; gates whose verifier subprocesses died with the kernel re-spawn fresh verifiers; verifier tokens issued before the crash were invalidated by `expire_orphan_verifier_tokens` during the recovery sweep, so any stray pre-crash subprocess that somehow re-presents its token is rejected with `AuthorityError::TokenExpired`. **Practical implication:** for tasks whose `prior_state` was `GatesPending`, the operator does not need to issue any extra command beyond `task resume` — the planner's first post-resume intent restores gate evaluation to a consistent state. For tasks whose `prior_state` was `Running`, the operator should also confirm with the planner whether any partial work was in flight (the planner may need to inspect its working tree for uncommitted changes before submitting the next intent).

---

### `task retry`

**Purpose:** Retry a `Failed` task — one where the planner self-reported failure via `IntentKind::ReportFailure`. Transitions the task from `Failed → Admitted` so it is re-queued for a new planner session. This is the **operator-directed retry** operation, distinct from recovery resume.

**Usage:** `raxis-cli task retry <task_id>`

**Behaviour:**
1. Opens operator socket; performs challenge-response handshake.
2. Sends `OperatorRequest::RetryTask { task_id }` (separate IPC variant from `ResumeTask`).
3. Kernel validates `task.state == TaskState::Failed` AND the containing initiative is non-terminal (`initiative.state ∈ {ApprovedPlan, Executing, Blocked}`). Failing preconditions return one of two envelope shapes per `peripherals.md` §3 "Operator socket":
   - **Task-state failure** → `OperatorResponse::Error { code: FAIL_TASK_NOT_RETRYABLE, detail: TaskNotRetryable { current_state } }`. CLI prints `"Cannot retry: task is in state <current_state> (must be Failed; Aborted/Cancelled tasks are non-retryable in v1 — see specs/v1/kernel-core.md INV-INIT-07)"` and exits non-zero.
   - **Initiative-state failure** → `OperatorResponse::Error { code: FAIL_INITIATIVE_TERMINAL, detail: InitiativeTerminal { initiative_state, terminal_criteria } }`. CLI prints `"Cannot retry: initiative is in terminal state <initiative_state> under criterion <terminal_criteria> — re-submit a new initiative via `raxis-cli plan submit`"` and exits non-zero. This case is most commonly hit under `AllTasksSucceeded` criteria where `evaluate_terminal_criteria` already moved the initiative to `Failed` synchronously with the task failure (see `kernel-core.md` §4.5 "Operator decision on partial failure" for the criterion-dependent applicability table); the `terminal_criteria` field in `detail` lets the operator immediately understand *why* the initiative is unrecoverable rather than having to look it up.
4. On success, kernel resets `session_id`, `evaluation_sha`, `base_sha`, `submitted_claims_json`, `admission_reserved_units`, and `actual_cost` on the task row, then transitions it `Failed → Admitted` via `transition_task`. The post-write `evaluate_terminal_criteria` hook fires automatically; under `MinSuccessCount` or `AllTasksTerminal` this may transition the initiative `Blocked → Executing` if `next_ready_tasks` becomes non-empty as a result. Emits `AuditEventKind::TaskTransitioned { from: Failed, to: Admitted, actor: Operator(<operator_id>), … }` plus `AuditEventKind::TaskRetried { task_id, initiative_id, retried_by, prior_failure_reason, at }` (full payload defined in `kernel-core.md` §4.6 `lifecycle::retry_task`); both audit writes are in the same store transaction as the row update. Returns `OperatorResponse::TaskRetried { task_id, initiative_id, transitioned_at }`.
5. Requires `RetryTask ∈ permitted_ops`. Authorisation failure returns `OperatorResponse::Error { code: UNAUTHORIZED, detail: OperationNotPermitted { operator_id, attempted_op: "RetryTask" } }` per the standard operator-permitted-ops gate (`kernel-store.md` §2.5.5 L1424 + `peripherals.md` §3 "Operator socket" auth flow). All other operator IPC commands return the same envelope on permitted-ops failure; this is documented once here for the `task retry` example.

**Note:** `Aborted` and `Cancelled` tasks cannot be retried in v1 — `Aborted` is terminal by infrastructure or operator decision, `Cancelled` is bulk-terminated by initiative-level operations (and per-task retry is meaningless when the initiative itself is terminal). `BlockedRecoveryPending` tasks use `task resume`, not `task retry`. After a successful retry, the operator should attach a planner session to the task (or wait for an existing session's next pickup) — `retry_task` only rewinds the task state, it does not re-spawn or re-attach planners. Each retry charges the lane budget afresh; there is no built-in retry cap in v1 (a future `policy.tasks.max_retries` field is deferred to v2).

---

**IPC discriminant table for operator task state operations:**

| CLI command | IPC message | Precondition | Transition | Handler |
|---|---|---|---|---|
| `task resume <id>` | `ResumeTask { task_id }` | `BlockedRecoveryPending` | `→ Running` | `recovery::resume_task` |
| `task retry <id>` | `RetryTask { task_id }` | `Failed` | `→ Admitted` | `initiatives::lifecycle::retry_task` |
| `task abort <id>` | `AbortTask { task_id }` | Any non-terminal | `→ Aborted` | `initiatives::lifecycle::abort_task` |

These are three distinct IPC variants — no single `ResumeTask` variant overloads multiple preconditions.

---

### `session create`

**Purpose:** Mint a planner session row in the kernel and return the session token to the operator. The operator is then responsible for spawning the planner subprocess with the token injected via the `RAXIS_SESSION_TOKEN` environment variable. v1 does **not** auto-spawn planners — planners are operator-supplied AI agents whose process lifecycle is owned by the operator's orchestration scripts; the kernel only owns the authentication credential.

This is the v1 answer to "how does a planner get a session token before its first intent." Gateway and verifier sessions are separate code paths (`spawn_gateway` at kernel boot, `spawn_verifier` on demand for each gate); only **planner** sessions flow through this CLI.

**Usage:** `raxis-cli session create --role planner --worktree-root <path> [--base-tracking-ref <ref>] [--task <task_id>] [--lineage-id <uuid>]`

- `--role planner` — required, must be the literal string `planner`. v1 rejects any other role on this CLI (`FAIL_ROLE_NOT_OPERATOR_CREATABLE`); gateway/verifier sessions are created elsewhere and never via operator IPC.
- `--worktree-root <path>` — required, absolute path to a git worktree the planner will operate in. Must exist; must contain `.git` (validated by `git -C <path> rev-parse --git-dir`); must be under one of the operator-allowed roots configured in `policy.toml` (`[sessions] allowed_worktree_roots = ["/home/operator/work", ...]`); a path outside any allowed root → `FAIL_WORKTREE_OUTSIDE_ALLOWED_ROOTS`.
- `--base-tracking-ref <ref>` — optional, the symbolic ref the kernel resolves into `sessions.base_sha` for stale-base re-resolution on `IntegrationMerge` intents. Defaults to `refs/heads/main` (per `kernel-core.md` Part 2.3 §`session.rs`). Resolution failure → `FAIL_BASE_REF_UNRESOLVED`.
- `--task <task_id>` — optional. When supplied, the kernel binds the new session to a single specific `Admitted` task; subsequent intents from this session whose `task_id` does not match are rejected with `FAIL_SESSION_TASK_MISMATCH`. When omitted, the session may submit intents for any `Admitted` task in any initiative the operator's policy entry can reach (the bind is established at first intent admission). The single-task mode is the standard v1 pattern; the unbound mode is reserved for test fixtures and future multi-task planner work.
- `--lineage-id <uuid>` — optional. Operator-supplied UUID v4 (hyphenated form, 36 ASCII bytes) identifying the **agent instance** this session belongs to. **Reuse the same `lineage_id` across sessions of the same logical agent** (e.g. a session-revoke + re-create cycle for a crashed agent that you want to resume under the same identity); use a **fresh** `lineage_id` for genuinely independent agents. The `lineage_id` is what per-lineage rate-limiting (`policy.escalation_max_per_window`) and quarantine (`policy.escalation_quarantine_threshold`) key on — sharing a lineage across independent agents pools their escalation budgets, which is almost always a mistake. When omitted, the CLI generates a fresh `Uuid::new_v4()` and prints it in the success summary so the operator can capture it. **Note:** there is no `initiative_id` parameter — sessions are not bound to initiatives at the session-row level; binding flows through `--task` (which implies an initiative) or through the first accepted intent's `task_id` (for unbound sessions). See `kernel-store.md` §2.5.5 "Lineage ownership and supply" for the full rationale.

**Behaviour:**
1. CLI opens operator socket; performs challenge-response handshake.
2. CLI sends `OperatorRequest::CreateSession { role: Role::Planner, worktree_root: PathBuf, base_tracking_ref: Option<String>, task_id: Option<TaskId>, lineage_id: LineageId }`. If `--lineage-id` was omitted, the CLI substitutes a freshly generated `Uuid::new_v4()` before sending.
3. Kernel handler (`handlers/operator::handle_create_session`) checks `permitted_ops` ∋ `CreateSession`, validates the worktree root, validates the `lineage_id` parses as a UUID v4 (`FAIL_INVALID_LINEAGE_ID` on failure), resolves `base_tracking_ref` (if provided) into a `base_sha`, then calls `authority::session::create_session(Role::Planner, Some(worktree_root), base_sha, base_tracking_ref, lineage_id, &cfg, &store)` — the canonical helper signature is extended to take `lineage_id: LineageId` (the column is `NOT NULL` in Table 4, so the parameter is required, not `Option`).
4. On success, kernel responds `OperatorResponse::SessionCreated { session_id, session_token, role, worktree_root, base_sha, base_tracking_ref, expires_at, lineage_id }`. The `session_token` is **256 bits of CSPRNG random as a 64-char lowercase hex string** (matching the storage shape in `sessions.session_token` per `kernel-store.md` §2.5.1 Table 4).
5. CLI prints all fields except the token to stdout (human-readable confirmation, including the `lineage_id` so the operator can record it for future reuse), and prints the token by itself to stderr with the leading marker `RAXIS_SESSION_TOKEN=` so the operator can pipe it into a `.env` file or capture it via shell redirection without it appearing in shell history under default zsh/bash settings. Example invocation: `raxis-cli session create --role planner --worktree-root /work/agent-1 --lineage-id $(uuidgen) 2>session-1.env`.
6. Audit: `AuditEventKind::SessionCreated { session_id, role, worktree_root, base_sha, base_tracking_ref, lineage_id, created_by_operator: <fingerprint>, bound_task_id }` (the `bound_task_id` field is `None` when `--task` was omitted).

**Token delivery to the planner.** The operator MUST deliver the token to the planner subprocess via a private channel — env var (`RAXIS_SESSION_TOKEN`), Unix file descriptor inheritance, or argv (least preferred — visible in `ps`). v1 does not constrain the choice; the trust boundary is the operator's process orchestration. The kernel never logs the token value (only the SHA-256 hash of it goes to the audit chain — `created_by_operator` audit field).

**Authorisation:** Requires `CreateSession ∈ permitted_ops`. Failure → `OperatorResponse::Error { code: UNAUTHORIZED, detail: OperationNotPermitted { operator_id, attempted_op: "CreateSession" } }` per the standard envelope.

---

### `session revoke`

**Purpose:** Mark a planner session as revoked, after which any further IPC frames presenting that token are rejected with `UNAUTHORIZED { reason: SessionRevoked }`. This is the v1 mechanism for terminating a misbehaving planner without killing the kernel; combine with `task abort` if the underlying task should also be terminated.

**Usage:** `raxis-cli session revoke <session_id>`

**Behaviour:**
1. CLI opens operator socket; performs challenge-response handshake.
2. CLI sends `OperatorRequest::RevokeSession { session_id }`.
3. Kernel handler (`handlers/operator::handle_revoke_session`) checks `permitted_ops`, then calls `authority::session::revoke_session(session_id, &store, &audit)` which executes `UPDATE sessions SET revoked_at = now() WHERE session_id = ? AND revoked_at IS NULL` inside one store transaction (INV-STORE-02) and appends `AuditEventKind::SessionRevoked { session_id, revoked_by_operator: <fingerprint>, revoked_at }` to the chain.
4. On success: `OperatorResponse::SessionRevoked { session_id, revoked_at }`. CLI prints `Session <session_id> revoked at <timestamp>`.
5. On precondition failure: if the session row does not exist → `OperatorResponse::Error { code: FAIL_SESSION_NOT_FOUND, detail: SessionNotFound { session_id } }`. If it was already revoked (idempotency hit — `rows_affected == 0`) → `OperatorResponse::Error { code: FAIL_SESSION_ALREADY_REVOKED, detail: SessionAlreadyRevoked { session_id, revoked_at } }`. Both are non-fatal from the operator's perspective (the desired end state is the same), but the CLI exits non-zero to make orchestration scripts notice the unexpected condition.
6. **Effect on in-flight IPC.** A planner that has an open connection holding an active stream is **not** disconnected synchronously — the kernel does not currently reach into the per-connection task to close the socket on revocation. The next IPC frame that flows through `ipc/auth.rs::validate` reads the now-revoked session row and is rejected with `UNAUTHORIZED { reason: SessionRevoked }`, which closes the connection. Practically this means a long-running inference call may complete before the planner sees the revocation; operators relying on hard cut-off semantics MUST also `task abort` the relevant task (which prevents further state writes from any subsequent intent regardless of session validity).

**Effect on `delegations`.** Active delegations on the revoked session remain rows in the `delegations` table for audit purposes; they cannot be exercised because every gated action goes through `validate` first. v1 does not eagerly mark delegations `Revoked`; this is by design (one source of truth — the session row).

**Authorisation:** Requires `RevokeSession ∈ permitted_ops`. Failure → `OperatorResponse::Error { code: UNAUTHORIZED, detail: OperationNotPermitted { operator_id, attempted_op: "RevokeSession" } }`.

---

### `delegation grant`

**Purpose:** Grant a planner session a specific `CapabilityClass` for a bounded TTL, scoped under a specific `delegating_role_id` whose ceiling in `policy.toml` constrains what may be granted. Until a delegation is granted, the planner cannot pass any gate that requires that capability class — its first attempt returns `FAIL_CAPABILITY_REQUIRED`. The standard operator workflow is `session create` → `delegation grant` × N → hand the token to the planner spawn.

**Usage:** `raxis-cli delegation grant --session <session_id> --capability <capability_class> --role <role_id> --ttl <seconds> [--scope-json <inline-json>]`

- `--session <session_id>` — required; the session that will receive the delegation. Must be active (not revoked, not expired).
- `--capability <capability_class>` — required; one of the canonical `CapabilityClass` enum names (e.g. `WriteSecrets`, `NetworkEgress`, `BreakGlass`). The full enum is defined in `raxis-types/src/capability.rs`; the kernel rejects any value not in the enum at deserialise time (`FAIL_UNKNOWN_CAPABILITY_CLASS`).
- `--role <role_id>` — required; the role under whose ceiling the grant is being made. Must be a key of `policy.role_ceilings`; the requested capability must be present in that role's ceiling bitmap. Roles are operator-defined; common v1 examples are `software-engineer`, `infra-operator`, `incident-responder`.
- `--ttl <seconds>` — required; integer seconds into the future. Must satisfy `0 < ttl <= policy.delegations.max_ttl_seconds` (default 86400 = 24h). The kernel computes `expires_at = now() + ttl` and stores it.
- `--scope-json <inline-json>` — optional; a free-form JSON document that scopes the capability beyond the class itself (e.g. `{"domains":["api.stripe.com"]}` for `NetworkEgress`). Schema is per-capability and lives in `raxis-types`. The kernel stores the raw JSON in `delegations.scope_json` and passes it to capability checks via `gates/claim.rs`.

**Behaviour:**
1. CLI opens operator socket; performs challenge-response handshake. The handshake establishes which operator is authenticated; the operator's **private** key (loaded from `--operator-key <path>` or the configured default keystore location — same key used by `raxis-cli policy sign` and `raxis-cli escalation approve`) must be available to the CLI process for the next step.
2. CLI builds the canonical signing-domain bytes per `kernel-store.md` §2.5.5 "Delegation grant signing domain on the operator socket" — the byte-exact concatenation `"RAXIS-V1-DELEGATION-GRANT" || 0x00 || session_id (UUID hyphenated) || 0x00 || capability_class || 0x00 || role_id || 0x00 || expires_at_le_u64 || 0x00 || scope_json_present_byte || (length-prefixed scope_json bytes if Some)`. CLI computes `signing_input = SHA-256(canonical_bytes)` and `operator_sig = Ed25519Sign(operator_private_key, signing_input)`.
3. CLI sends `OperatorRequest::GrantDelegation { session_id, capability_class, delegating_role_id, expires_at, scope_json, operator_sig }`. The `op_token` (operator session token from step 1's handshake) is carried in the IPC envelope header per the standard operator socket auth.
4. Kernel handler (`handlers/operator::handle_grant_delegation`) checks `permitted_ops ∋ GrantDelegation`, then calls `authority::delegation::grant_delegation(req, &store, &policy, &audit)` (full contract in `kernel-core.md` Part 2.3 §`authority/delegation.rs`). The handler runs the now-six-step sequence: session validity → policy ceiling check → operator-signature verification (step 2.5) → TTL bounds check → uniqueness check → insert + audit (single transaction, INV-STORE-02).
5. On success: `OperatorResponse::DelegationGranted { delegation_id, granted_at, expires_at, capability_class }`. CLI prints `Delegation <delegation_id> granted: session=<session_id> capability=<class> role=<role_id> expires=<timestamp>`.
6. On precondition failure, the response is `OperatorResponse::Error { code, detail }` with one of the failure codes enumerated in `kernel-store.md` §2.5.5 operator-error envelope: `FAIL_SESSION_INVALID`, `FAIL_CAPABILITY_ABOVE_CEILING`, `FAIL_DELEGATION_SIGNATURE_INVALID`, `FAIL_DELEGATION_TTL_OUT_OF_RANGE`, `FAIL_DELEGATION_ALREADY_ACTIVE`, `FAIL_UNKNOWN_CAPABILITY_CLASS`. The CLI deserialises `detail` and renders a human-readable message. **`FAIL_DELEGATION_SIGNATURE_INVALID` almost always indicates a CLI/kernel disagreement on the canonical-bytes serialisation** — implementers MUST add a regression test that round-trips the canonical bytes between the CLI signer and the kernel verifier on every supported `(scope_json present/absent, capability class, role id)` cross-product before merging changes to either side.
7. Audit: `AuditEventKind::DelegationGranted { delegation_id, session_id, capability_class, delegating_role_id, granted_by_operator: <fingerprint>, expires_at, operator_sig_sha256, scope_json_sha256 }` (both the signature and the scope JSON are stored as SHA-256 in the audit event, with the raw signature persisted in `delegations.operator_signature` and the raw scope JSON in `delegations.scope_json` — keeps the audit chain compact and avoids leaking large scope payloads into a frequently-rotated segment).

**Re-granting after expiry or revocation.** v1 has no in-place "renew" path. To re-grant after expiry, the operator submits a fresh `delegation grant` for the same `(session, capability)` — the prior row's `status` will already be `Expired` (TTL passed), so the UNIQUE constraint (`status IN ('Active', 'StaleOnNextUse')`) does not block. After a `RotateEpoch`, all `Active` delegations transition to `StaleOnNextUse` per `mark_stale_on_epoch_advance`; the planner gets one final use with `warn_delegation_stale = true`, after which a new `delegation grant` is required. There is no `RevokeDelegation` operator IPC in v1; deferred to v2 alongside the broader `policy.delegations.lifecycle` features.

**Authorisation:** Requires `GrantDelegation ∈ permitted_ops`. Failure → `OperatorResponse::Error { code: UNAUTHORIZED, detail: OperationNotPermitted { operator_id, attempted_op: "GrantDelegation" } }`.

---

### `epoch advance`

**Purpose:** Advance the policy epoch by loading and verifying a new signed policy artifact, sweeping all active delegations to `StaleOnNextUse`, invalidating all session prompt caches, swapping the in-memory policy bundle and domain allowlist, and signalling the gateway to reload.

**Usage:** `raxis-cli epoch advance --policy <path> --sig <path>`

Both arguments are **required**. There is no implicit staged location. The kernel canonicalises both paths and rejects any path that does not resolve under `<data_dir>/policy/` (`PolicyError::PathOutsideDataDir`); operators stage new artifacts inside `<data_dir>/policy/` (e.g. `policy.toml.next` + `policy.toml.next.sig`) before invoking the command. Capturing the exact paths in shell history and in the audit record is intentional — it ties an epoch-advance event to a specific on-disk artifact pair without an implicit "current staged" mutable pointer.

**Behaviour:**
1. CLI opens the operator socket; performs the challenge-response handshake (`peripherals.md` operator socket auth). The handshake establishes the `OperatorId` of the invoker (looked up from `[[operators.entries]]` in the current policy artifact); this `OperatorId` is forwarded to the kernel as `triggered_by` in step 2.
2. CLI sends `OperatorRequest::RotateEpoch { policy_path: PathBuf, sig_path: PathBuf }` carrying the resolved absolute paths from the `--policy` / `--sig` arguments. (Empty payload is **not** valid; the kernel rejects `RotateEpoch` IPC messages with empty paths at the deserialiser before reaching the handler.)
3. Kernel handler (`handlers/operator::handle_rotate_epoch`) calls `policy_manager::advance_epoch(policy_path, sig_path, &triggered_by, &registry, &ctx)` (full contract in `kernel-core.md` §`policy_manager.rs`). The handler runs the four-phase sequence: (Phase 0) verify the artifact signature, epoch-monotonicity, and TOML shape; (Phase 1) one SQL transaction holding the `Store` mutex, doing the delegations sweep + session-prompt invalidation + `policy_epoch` row insert + `PolicyEpochAdvanced` audit append; (Phase 2) `ArcSwap` swaps for `ctx.policy` and `ctx.allowlist_cache`; (Phase 3) best-effort `GatewayMessage::EpochAdvanced` signal.
4. On success, kernel responds `OperatorResponse::EpochAdvanced { new_epoch_id, n_delegations_marked_stale, n_sessions_invalidated, policy_sha256 }`. CLI prints all four values so the operator can confirm the artifact identity and the scope of the sweep.
5. On failure, kernel responds `OperatorResponse::Error { code, detail }` where `code` is one of `FAIL_POLICY_SIGNATURE_INVALID`, `FAIL_POLICY_EPOCH_REPLAY`, `FAIL_POLICY_MALFORMED`, `FAIL_PATH_OUTSIDE_DATA_DIR`, or `FAIL_STORE_WRITE` (Phase 0 rejection codes vs Phase 1 commit failure; per the audit-on-rejection contract in `kernel-core.md`, the corresponding `PolicyAdvanceRejected` or `PolicyAdvanceFailed` audit event is appended before the kernel returns). CLI exits non-zero and prints the error.
6. Active planner sessions are **not** disconnected — their next inference request triggers prompt reassembly under the new epoch (per `prompt::epoch_binding` flow in `kernel-core.md`). Active delegations are flagged `StaleOnNextUse`: the next gated action against each delegation passes once with `warn_delegation_stale = true` in the `IntentResponse` (see `peripherals.md` §3.1), then must be renewed before the following action.

**Audit event name correction:** the canonical event kind is `AuditEventKind::PolicyEpochAdvanced` (with payload `{ old_epoch, new_epoch, policy_sha256, signed_by_authority, triggered_by, advanced_at, n_delegations_marked_stale, n_sessions_invalidated }`). Older draft text using `AuditEventKind::EpochAdvanced` is non-canonical and is being swept out of all spec sites in this revision.

---

### `audit verify`

**Purpose:** Verify the integrity of the JSONL audit log chain. Does not connect to the kernel.

**Usage:** `raxis-cli audit verify [--log-path <path>]`

Default log path: `<data_dir>/audit/segment-000.jsonl` (the initial segment created at genesis; see `kernel-store.md` §2.5.2).

**Behaviour:**
1. Reads the JSONL segment file line by line (one audit record per line).
2. For each line: parses the record, computes SHA-256 of the raw line bytes (including trailing newline), and checks it against `next_line.prev_sha256`.
3. On chain break: prints `Chain break at seq=<n>: expected <hash>, got <hash>`. Continues verifying the remainder.
4. Prints a summary: total records, gaps detected, chain breaks detected.
5. Exit code 0 = clean chain; non-zero = chain has breaks or gaps.

**Multi-segment installations:** `audit verify` operates on one segment file per invocation. Cross-segment chain integrity — verifying that the first line of `segment-001.jsonl` correctly chains from the last line of `segment-000.jsonl` — is the responsibility of `raxis-audit-tools`, not the CLI. The CLI does not implement cross-segment stitching. To verify a full multi-segment audit trail, use `raxis-audit-tools verify-chain --audit-dir <data_dir>/audit/`, which walks all `segment-*.jsonl` files in creation order and validates the inter-segment `prev_sha256` link. The per-line algorithm is identical to single-segment verification.

**Note:** `audit verify` only checks chain integrity for the file given. It does not verify that audit records match SQLite state. Use `recovery::reconcile` (kernel-internal) for state-vs-audit reconciliation.

---

### `audit gaps`

**Purpose:** Report reconciliation gaps — JSONL records marked `reconstructed: true` by `recovery::reconcile`.

**Usage:** `raxis-cli audit gaps [--log-path <path>]` (defaults to the same path convention as `audit verify`)

Prints a table of gap records with their `missing_seq` values and reconstructed event kinds.

---

## §4.2 — Genesis Ceremony Step-by-Step

This section is the normative walkthrough for a first-time operator setting up RAXIS v1 from scratch.

### Prerequisites

- The `raxis-kernel` and `raxis-cli` binaries are installed and on `$PATH`.
- The operator has generated their own Ed25519 keypair on a machine they control (the private key should never touch the machine running the kernel if possible, but v1 permits co-location).
- The data directory (`~/.raxis` by default) is empty.

### Step 1 — Run genesis

```bash
raxis-cli genesis --operator-pubkey ~/my-operator-key.pub
```

This generates all kernel keys and a skeleton `policy.toml`. Review the output file at `~/.raxis/policy/policy.toml` before proceeding.

### Step 2 — Edit `policy.toml`

Add at minimum:
- `[[gates]]` entries for each gate type you want to enforce.
- `[[tasks]]` entries if you want a global task allowlist (optional in v1 — the signed plan is the authoritative task list).
- Domain allowlist entries for provider URLs.
- Budget limits.

Do not modify `authority_pubkey` or `quality_pubkey` — these were written by genesis and match the generated keypairs.

### Step 3 — Sign the policy

```bash
raxis-cli policy sign ~/.raxis/policy/policy.toml --key ~/my-operator-key
```

This writes `~/.raxis/policy/policy.sig`. The kernel verifies this signature at boot. If `policy.sig` is absent or invalid, the kernel will not start.

### Step 4 — Start the kernel

```bash
raxis-kernel --data-dir ~/.raxis
```

The kernel loads keys, verifies `policy.sig`, binds all three sockets, and is ready.

### Step 5 — Write and sign a plan

Create `~/my-plan/plan.toml` following the plan schema (see §2.5.3 and the fixture examples in §4.3). Then:

```bash
raxis-cli policy sign ~/my-plan/plan.toml --key ~/my-operator-key
```

### Step 6 — Submit and approve

```bash
raxis-cli plan submit initiative-001 ~/my-plan
raxis-cli plan approve initiative-001
```

Tasks are now scheduled. The planner session can begin.

### Re-genesis / key rotation

**Always stop the kernel before any key rotation.** Run:

```bash
raxis-cli genesis --rotate <key-family>
# After the kernel restarts, stage the re-signed policy artifact under
# <data_dir>/policy/ (e.g. as policy.toml.next + policy.toml.next.sig) then:
raxis-cli epoch advance \
  --policy <data_dir>/policy/policy.toml.next \
  --sig    <data_dir>/policy/policy.toml.next.sig
```

---

## §4.3 — Integration Test Fixtures

The canonical fixtures live at `raxis/fixtures/`. Each fixture is a minimal valid plan TOML that exercises a specific invariant or system behaviour. The v1 test matrix (§1.3 in `philosophy.md`) cross-references these fixtures by name.

### Fixture schema

All fixture files follow the signed plan schema defined in §2.5.3. They are not pre-signed — test harnesses sign them with a test key generated at test setup time.

---

### `fixtures/minimal_plan.toml` — Simplest valid plan

**Exercises:** INV-INIT-06 (plan immutability), INV-TASK-PATH-01 (path scope admission), INV-SCHED-01 (admit called only from approve_plan).

```toml
[plan]
initiative_id  = "test-minimal-001"
description    = "Minimal single-task plan with no gates and no dependencies"
version        = "1"

[[tasks]]
task_id        = "task-alpha"
description    = "Implement the feature"
intent_kinds   = ["SingleCommit", "CompleteTask"]
path_allowlist = ["src/", "tests/"]
predecessors   = []
gates          = []

terminal_criteria = "AllTasksSucceeded"
```

**Expected terminal state:** `initiative.status = Completed` after `task-alpha` reaches `Completed`.

**Key checks:**
- `create_session` with `worktree_root` pointing to a valid git repo succeeds.
- `IntentRequest { intent_kind: "SingleCommit", task_id: "task-alpha" }` with a path outside `["src/", "tests/"]` → `FAIL_PATH_POLICY_VIOLATION`.
- `IntentRequest` with `task_id: "task-unknown"` → `FAIL_UNKNOWN_TASK`.
- `CompleteTask` with all paths in scope and no gate requirements → accepted; task transitions to `Completed`.

---

### `fixtures/gated_plan.toml` — Single gate

**Exercises:** INV-03 (witness SHA binding), INV-07 (kernel-derived claims), gate evaluation lifecycle, `FAIL_MISSING_WITNESS`, `FAIL_INSUFFICIENT_WITNESS`.

```toml
[plan]
initiative_id  = "test-gated-001"
description    = "Single task with one TestCoverage gate"
version        = "1"

[[tasks]]
task_id        = "task-beta"
description    = "Implement and test the feature"
intent_kinds   = ["SingleCommit", "CompleteTask"]
path_allowlist = ["src/", "tests/"]
predecessors   = []
gates          = [{ gate_type = "TestCoverage", threshold = 80 }]

terminal_criteria = "AllTasksSucceeded"
```

**Expected terminal state:** `initiative.status = Completed` only after `task-beta` has a `Pass` witness for `TestCoverage` bound to the final `head_sha`.

**Key checks:**
- `CompleteTask` before a witness exists → `FAIL_MISSING_WITNESS`.
- `CompleteTask` with a witness bound to a different SHA → kernel rejects the CompleteTask (INV-03 — witness is SHA-bound, not reusable).
- A witness with `result_class: "Fail"` (coverage below threshold) → `FAIL_INSUFFICIENT_WITNESS`.
- A witness with `result_class: "Pass"` bound to the correct `evaluation_sha` → `CompleteTask` accepted.

---

### `fixtures/dag_plan.toml` — DAG with dependencies

**Exercises:** DAG scheduling, predecessor-gate blocking, `scheduler::next_ready_tasks`, task lifecycle across multiple tasks.

```toml
[plan]
initiative_id  = "test-dag-001"
description    = "Three-task dependency chain"
version        = "1"

[[tasks]]
task_id        = "task-1-foundation"
description    = "Build the foundation layer"
intent_kinds   = ["SingleCommit", "CompleteTask"]
path_allowlist = ["src/foundation/"]
predecessors   = []
gates          = []

[[tasks]]
task_id        = "task-2-feature"
description    = "Build the feature on top"
intent_kinds   = ["SingleCommit", "CompleteTask"]
path_allowlist = ["src/feature/"]
predecessors   = ["task-1-foundation"]
gates          = []

[[tasks]]
task_id        = "task-3-integration"
description    = "Integration wiring"
intent_kinds   = ["SingleCommit", "CompleteTask"]
path_allowlist = ["src/integration/", "tests/integration/"]
predecessors   = ["task-1-foundation", "task-2-feature"]
gates          = []

terminal_criteria = "AllTasksSucceeded"
```

**Expected terminal state:** `initiative.status = Completed` after all three tasks complete in dependency order.

**Key checks:**
- `task-2-feature` is in `Admitted` state but is **not returned by `next_ready_tasks`** until `task-1-foundation` is `Completed`. (`Blocked` is an initiative-level state, not a task state — individual tasks with unsatisfied predecessors remain `Admitted`.)
- `task-3-integration` is similarly in `Admitted` with two unsatisfied predecessor edges; `next_ready_tasks` does not surface it until both are `Completed`.
- Attempting to submit an intent for a task not returned by `next_ready_tasks` → `FAIL_TASK_NOT_RUNNING` (the task is `Admitted`, not `Running`).
- After `task-1-foundation` completes, the next `next_ready_tasks` query surfaces `task-2-feature` (now all predecessor edges satisfied); a planner session may claim it.

---

### `fixtures/integration_plan.toml` — IntegrationMerge task

**Exercises:** `IntentKind::IntegrationMerge` 5-predicate topology check, stale-base check, `FAIL_STALE_BASE`, `FAIL_INVALID_COMMIT_TOPOLOGY`.

```toml
[plan]
initiative_id  = "test-integration-001"
description    = "Two agent tasks plus one integration merge task"
version        = "1"

[[tasks]]
task_id        = "task-agent-a"
description    = "Agent A feature branch"
intent_kinds   = ["SingleCommit", "CompleteTask"]
path_allowlist = ["src/feature-a/"]
predecessors   = []
gates          = []

[[tasks]]
task_id        = "task-agent-b"
description    = "Agent B feature branch"
intent_kinds   = ["SingleCommit", "CompleteTask"]
path_allowlist = ["src/feature-b/"]
predecessors   = []
gates          = []

[[tasks]]
task_id        = "task-integration"
description    = "Merge agent branches onto main"
intent_kinds   = ["IntegrationMerge", "CompleteTask"]
path_allowlist = ["src/feature-a/", "src/feature-b/"]
predecessors   = ["task-agent-a", "task-agent-b"]
gates          = []

terminal_criteria = "AllTasksSucceeded"
```

**Expected terminal state:** All three tasks `Completed`; initiative `Completed`.

**Key checks:**
- `IntegrationMerge` intent where `head_sha` is not a merge commit → `FAIL_INVALID_COMMIT_TOPOLOGY`.
- `IntegrationMerge` intent where the merge base has advanced past `sessions.base_tracking_ref` → `FAIL_STALE_BASE`.
- Valid merge commit (exactly two parents, both fast-forward reachable from the integration branches, merge base equals `sessions.base_sha`) → accepted.
- `task-integration` is in `Admitted` state with two unsatisfied predecessor edges; `next_ready_tasks` does not surface it until both agent tasks are `Completed`.

---

### Test harness notes

- All fixtures are signed at test-harness setup time with a test-generated Ed25519 keypair. The test harness runs a `genesis` step with the test key before each fixture test.
- Each fixture test runs the kernel in a temporary `--data-dir` to ensure isolation.
- Gate fixtures (`gated_plan.toml`) use a test verifier binary that reads `RAXIS_GATE_TYPE` and returns a configurable `result_class` via a control file, making gate outcomes deterministic.
- All fixture tests must pass before a v1 release gate is signed (§1.4 in `philosophy.md`).
