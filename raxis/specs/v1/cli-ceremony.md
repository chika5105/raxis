# RAXIS — Part 4: CLI, Genesis Ceremony, and Fixtures

> **Scope:** `raxis-cli` subcommands and their normative behaviour (§4.1), the genesis key ceremony step-by-step (§4.2), and the canonical integration test fixtures with their v1 test matrix cross-references (§4.3).
>
> **Navigation:** [README](../../README.md) | [Part 2 Store](kernel-store.md) | [Part 3](peripherals.md) | [Planner API](planner-api.md)
>
> **Authority:** Where this file and `kernel-store.md` conflict on key file names, formats, or paths, `kernel-store.md` §2.5.4 wins. Where this file describes CLI subcommand behaviour that drives the operator auth protocol, `kernel-store.md` §2.5.5 wins on the wire format.

---

## §4.1 — `raxis-cli` Subcommands

`raxis-cli` is the operator-facing binary. All operator interactions with the kernel go through this tool. It communicates exclusively over the operator UDS (`<data_dir>/sockets/operator.sock`), performing the challenge-response handshake on every invocation.

### Global flags

```
raxis-cli [--data-dir <path>] [--socket <path>] <subcommand>
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
   - `[[operators.entries]]` = the registered operator entry with `permitted_ops = ["CreateInitiative", "ApprovePlan", "RejectPlan", "AbortInitiative", "AbortTask", "ResumeTask", "RetryTask", "GrantDelegation", "ApproveEscalation", "DenyEscalation", "RevokeSession", "RotateEpoch"]` (minimal **full-v1** starter set — omit keys only if you intentionally deny that capability)
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
- For any key: prints "You must advance the policy epoch before restarting. Run: `raxis-cli epoch advance`."
- Does **not** automatically advance the epoch — that is a separate explicit step.

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
2. Sends `ResumeTask { task_id }` (operator IPC variant).
3. Kernel calls `recovery::resume_task(task_id, operator_id)` — validates `task.state == TaskState::BlockedRecoveryPending`. Any other state → `FAIL_TASK_NOT_RESUMABLE { current_state }`.
4. Kernel transitions task `BlockedRecoveryPending → Running`; emits `AuditEventKind::TaskResumed`.
5. Requires `ResumeTask ∈ permitted_ops`.

**Note:** After `task resume`, the operator must attach a planner session to the task to continue work. The kernel does not automatically reconnect the prior session (it may have been terminated at crash time).

---

### `task retry`

**Purpose:** Retry a `Failed` task — one where the planner self-reported failure via `IntentKind::ReportFailure`. Transitions the task from `Failed → Admitted` so it is re-queued for a new planner session. This is the **operator-directed retry** operation, distinct from recovery resume.

**Usage:** `raxis-cli task retry <task_id>`

**Behaviour:**
1. Opens operator socket; performs challenge-response handshake.
2. Sends `RetryTask { task_id }` (separate IPC variant from `ResumeTask`).
3. Kernel validates `task.state == TaskState::Failed`. Any other state → `FAIL_TASK_NOT_RETRYABLE { current_state }`.
4. Kernel transitions task `Failed → Admitted`; emits `AuditEventKind::TaskRetried { operator_id }`.
5. Requires `RetryTask ∈ permitted_ops`.

**Note:** `Aborted` tasks cannot be retried in v1 — abort is terminal. `BlockedRecoveryPending` tasks use `task resume`, not `task retry`.

---

**IPC discriminant table for operator task state operations:**

| CLI command | IPC message | Precondition | Transition | Handler |
|---|---|---|---|---|
| `task resume <id>` | `ResumeTask { task_id }` | `BlockedRecoveryPending` | `→ Running` | `recovery::resume_task` |
| `task retry <id>` | `RetryTask { task_id }` | `Failed` | `→ Admitted` | `initiatives::lifecycle::retry_task` |
| `task abort <id>` | `AbortTask { task_id }` | Any non-terminal | `→ Aborted` | `initiatives::lifecycle::abort_task` |

These are three distinct IPC variants — no single `ResumeTask` variant overloads multiple preconditions.

---

### `epoch advance`

**Purpose:** Advance the policy epoch, invalidating all epoch-bound sessions and cached witnesses.

**Usage:** `raxis-cli epoch advance`

**Behaviour:**
1. Opens operator socket; performs challenge-response handshake.
2. Sends `RotateEpoch {}`.
3. Kernel increments `epoch_id`, marks all active sessions' `prompt_epoch_valid = false`, and logs `AuditEventKind::EpochAdvanced`.
4. Prints the new epoch ID.
5. Active planner sessions are not disconnected — their next inference request will trigger prompt reassembly under the new epoch.

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
raxis-cli epoch advance    # after kernel restarts
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
