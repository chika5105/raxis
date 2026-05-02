# RAXIS — Part 3: Planner, Gateway, and Verifier Specifications

> **Scope:** The three non-kernel processes that interact with the kernel over UDS. §3.1 covers the planner IPC contract and system-prompt API. §3.2 covers the gateway wire format. §3.3 covers the verifier subprocess contract.
>
> **Navigation:** [README](../../README.md) | [Part 2 Core](kernel-core.md) | [Part 2 Store](kernel-store.md) | [Planner API](planner-api.md) | [Part 4](cli-ceremony.md)
>
> **Authority:** Where this file and `kernel-core.md` conflict on IPC message shapes, this file wins — it is the client-facing contract. Where this file and `kernel-store.md` conflict on DDL-backed fields (e.g. session token format, sequence numbers), `kernel-store.md` wins.

> **Normative wire format — single source of truth:**
> All IPC between kernel, planner, gateway, and verifier uses **bincode-encoded Rust types preceded by a 4-byte little-endian length prefix** (excluding the prefix itself). This is implemented in `raxis-ipc::frame`. The codec is `bincode` (serde-compatible, no schema version field in v1). All JSON objects in this document are **human-readable projections** of the underlying `raxis-ipc` types for specification clarity — they are not the wire encoding. An implementation that sends bare JSON on the UDS is non-conformant. Where a JSON field name below differs from the Rust struct field name in `raxis-ipc`, the Rust name wins.

---

## §3.1 — Planner IPC Contract

### What the planner is

The planner is an LLM session running as a subprocess of or alongside the kernel. It is **not** a compiled binary in the RAXIS repository — it is the model-side participant in the kernel IPC protocol. Part 3.1 is the normative contract for that protocol: what the planner must send, what it will receive, and how it must behave.

The planner system prompt is assembled by the kernel (`prompt/assembler.rs`) and injected at session start. The machine-readable API specification — the portion of the system prompt that defines error codes, retry rules, and remediation actions — is in [`planner-api.md`](planner-api.md). That file is designed to be injected verbatim.

### Session lifecycle

```
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
  "submitted_claims": [
    { "claim_type": "TestSuite", "evidence_ref": "<witness blob hash>" }
  ],
  "justification":    "<free text, max 2048 chars; required for ReportFailure>",
  "idempotency_key":  "<uuid-v4; optional; for safe retry>"
}
```

**Field rules:**
- `sequence_number` — must be exactly `prev_accepted_sequence + 1`. Gaps or reuse → `UNAUTHORIZED`.
- `envelope_nonce` — 16 random bytes, hex. Must be globally unique per `(session_id, nonce)` pair within the nonce cache TTL (§2.5.1 Table 16). Reuse → `UNAUTHORIZED`.
- `base_sha` and `head_sha` — required for all intent kinds except `ReportFailure`. For `CompleteTask`, `base_sha` is accepted but ignored by the kernel (see `kernel-store.md` §2.5.8 `base_sha` disposition). For `SingleCommit`, `base_sha == head_sha` is a valid "no committed changes yet" intent (empty diff — path check passes vacuously per §2.5.8 edge-case table). For non-empty `SingleCommit` (`base_sha != head_sha`): the kernel enforces `parent(head_sha) == base_sha` via `vcs::rev_parse_parent` — i.e. exactly one new commit on top of `base_sha`. Submitting a `base_sha` that is an ancestor of `head_sha` but not its direct parent is rejected with `HandlerError::InvalidShaRange`. **This means `SingleCommit` is truly single-commit: one intent = one commit. Multi-commit ranges require a different `IntentKind` (not in v1).**
- `submitted_claims` — may be empty `[]` if the task's gate set has no active claim requirements. Providing claims when none are required is accepted (they are ignored).
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

> **Encoding reminder:** This JSON is the normative wire projection of `IpcMessage::KernelResponse(IntentResponse)` in `raxis-ipc`. The structural shape mirrors the Rust enum normatively defined in `philosophy.md` `crates/types/src/intent.rs` (two variants — `Accepted` and `Rejected`); the `outcome` JSON string is the discriminant. Wire fields are partitioned into:
>
> - **Envelope fields** (added by `raxis-ipc`'s frame serialiser, common to every IPC message — see `philosophy.md` `crates/types/src/envelope.rs`): `sequence_number`. The planner correlates a response to its prior request by matching `sequence_number`; the kernel does not echo `task_id` on the wire because correlation is already complete via the envelope.
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
| `remaining_budget` | payload | `Accepted` only | `BudgetSnapshot` JSON object, or `null` on `Rejected` | The lane's budget snapshot after `consume_budget` ran for this intent (or after the existing-reservation branch decided not to charge again — see `kernel-core.md` `handlers/intent.rs` "Budget check and reservation"). The inner shape is the JSON serialisation of the `BudgetSnapshot` Rust struct (`philosophy.md` `crates/types/src/intent.rs`); units are admission units per `kernel-core.md` §3.5 / `kernel-store.md` §2.5.7. The planner uses this to self-throttle: estimate the cost of the next intent and avoid submitting if `remaining_budget < estimate`. **Always `null` on `Rejected`** — rejected intents do not consume budget, so there is no post-consume snapshot to report. |
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

```rust
// raxis-types/src/operator.rs (normative)
enum OperatorResponse {
    // ... per-command success variants, e.g. EpochAdvanced { … }, TaskRetried { … } ...
    Error {
        code: OperatorErrorCode,    // string-tagged enum (see table below) — wire form is the bare code string
        detail: OperatorErrorDetail,// serde-tagged enum, one variant per code, carrying the code's structured fields; never a free-form string
    },
}

enum OperatorErrorDetail {
    // Tag matches the OperatorErrorCode value; field set is fixed per variant.
    TaskNotResumable    { current_state: TaskState },
    TaskNotRetryable    { current_state: TaskState },
    InitiativeTerminal  { initiative_state: InitiativeState, terminal_criteria: TerminalCriteria },
    // policy-advance failure details (see `cli-ceremony.md` §`epoch advance`):
    PolicySignatureInvalid { artifact_path: PathBuf },
    PolicyEpochReplay      { presented_epoch: u64, current_epoch: u64 },
    PolicyMalformed        { parser_message: String },
    PathOutsideDataDir     { offending_path: PathBuf, data_dir: PathBuf },
    StoreWrite             { sql_error: String },
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
| `FAIL_INITIATIVE_TERMINAL` | `InitiativeTerminal { initiative_state, terminal_criteria }` | `lifecycle::retry_task` precondition 4 | `task retry` precondition failed — the containing initiative is in a terminal state (`Completed`/`Failed`/`Aborted`). `initiative_state` is the actual terminal state; `terminal_criteria` is the criterion that drove the initiative there (so the operator immediately sees, e.g., that `AllTasksSucceeded` synchronously moved the initiative to `Failed` after the task failed). See `kernel-core.md` §4.6 `lifecycle::retry_task` precondition 4 and §4.5 "Operator decision on partial failure" for the criterion-dependent applicability table. |
| `FAIL_POLICY_SIGNATURE_INVALID` | `PolicySignatureInvalid { artifact_path }` | `policy_manager::advance_epoch` Phase 0 step 1 | New policy artifact's Ed25519 signature did not verify against the authority pubkey. |
| `FAIL_POLICY_EPOCH_REPLAY` | `PolicyEpochReplay { presented_epoch, current_epoch }` | `policy_manager::advance_epoch` Phase 0 step 1 (loader epoch monotonicity check) | New artifact's `meta.epoch` is not strictly greater than `policy_epoch_history` MAX. |
| `FAIL_POLICY_MALFORMED` | `PolicyMalformed { parser_message }` | `policy_manager::advance_epoch` Phase 0 step 1 (TOML parse / schema check) | New artifact failed TOML parse or required-block validation. |
| `FAIL_PATH_OUTSIDE_DATA_DIR` | `PathOutsideDataDir { offending_path, data_dir }` | `policy_manager::advance_epoch` Phase 0 path canonicalisation | One of `--policy` / `--sig` resolved to a path outside `<data_dir>/policy/`. |
| `FAIL_STORE_WRITE` | `StoreWrite { sql_error }` | `policy_manager::advance_epoch` Phase 1 commit failure | A SQL write inside the Phase 1 transaction failed; the transaction was rolled back. |
| `UNAUTHORIZED` | `OperationNotPermitted { operator_id, attempted_op }` | Every operator IPC dispatcher (per-op `permitted_ops` gate, `kernel-store.md` §2.5.5 L1424) | The authenticated operator's `permitted_ops` list does not include the requested op. `attempted_op` is the operator IPC variant name (e.g. `"RetryTask"`, `"RotateEpoch"`) so the operator can confirm which entry to add to their policy entry. **Note:** the bare wire string `UNAUTHORIZED` is shared with the *planner* socket's `PlannerErrorCode::UNAUTHORIZED` variant (planner-facing table above), but the two enums live in different Rust types (`OperatorErrorCode` vs `PlannerErrorCode`) and carry different `detail` shapes — the socket the message arrived on disambiguates which decoder to use. |

Adding a new operator error code requires adding both a new `OperatorErrorCode` enum value and a matching `OperatorErrorDetail` variant in the same PR — the spec disallows codes whose `detail` shape is undefined.

Normative operator CLI behaviour and the full per-command IPC discriminant table are in `cli-ceremony.md`.

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

## §3.2 — Gateway Wire Format

### What the gateway is

The gateway is a subprocess spawned by the kernel at startup. It holds provider API credentials (loaded from `<data_dir>/providers/`) and proxies all external provider calls on the kernel's behalf. The planner has no direct path to provider APIs (INV-02A, INV-02B).

The gateway communicates with the kernel exclusively over the gateway UDS (`<data_dir>/sockets/gateway.sock`). It authenticates using a `gateway_process_token` issued at spawn time (distinct from planner session tokens).

**Inference path:** When the kernel needs to make a model inference call, it constructs the provider-specific request body (via `provider/` adapter) and sends it to the gateway as a `FetchRequest` with `fetch_kind: "Inference"`. The gateway is not aware of the semantic content of the request — it proxies bytes and injects credentials. `InferenceRequest` in `kernel-core.md` refers to the kernel-internal abstraction; `FetchRequest` here is the kernel→gateway wire message. There is no separate `InferenceRequest` on the gateway UDS — all external calls are `FetchRequest`.

### Spawn model

```
kernel bootstrap::run →
    spawn_gateway(gateway_binary_path, gateway_process_token, gateway_socket_path)
        → env: RAXIS_GATEWAY_TOKEN=<hex>, RAXIS_GATEWAY_SOCKET=<path>
        → gateway connects to gateway.sock, authenticates with token
        → kernel records gateway as ready
```

The gateway token is a 32-byte CSPRNG value generated at each boot. It is not stored in SQLite — it is in-memory only. If the gateway subprocess dies and is restarted, a new token is issued.

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

---

## §3.3 — Verifier Subprocess Contract

### What the verifier is

The verifier is a short-lived subprocess spawned by `src/gates/verifier_runner.rs` to evaluate one gate for one task. It is **not** a persistent service — it runs, submits one `WitnessSubmission`, and exits.

The verifier binary is operator-provided (configured in `[[gates]]` as `verifier_command`). RAXIS does not ship verifier binaries — operators write or install them. The contract this section defines is the interface that every verifier binary must implement.

### Input: `VerifierSpawnEnvelope`

All input arrives via environment variables. See `kernel-store.md` §2.5.6 for the normative env var table. Summary:

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

| Variant | Meaning |
|---|---|
| `Pass` | Gate evaluation ran and evidence meets the policy threshold |
| `Fail` | Gate evaluation ran but evidence does not meet threshold (e.g. coverage below minimum). Gate outcome is `Fail`. |
| `Error` | Verifier could not complete evaluation due to an environmental error (build failure, test runner crash). Not a gate outcome — kernel re-queues for retry (up to `max_verifier_retries`, default 2). |

These are the **only** valid `result_class` values in v1. Any other value → witness rejected, `verifier_run_token` consumed (treat as malformed submission).

- `body` — gate-type-specific structured evidence. Schema is defined per `GateType` in `raxis-types/src/witness.rs`. The kernel validates the body schema; malformed bodies → witness rejected, verifier token consumed.
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
