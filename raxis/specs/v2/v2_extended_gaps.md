# RAXIS V2 — Extended Gaps & Forward Features

> **Last updated:** 2026-05-09
> **Scope:** Items discovered during the V2.5 code audit that are
> **not covered** by [`V2_GAPS.md`](V2_GAPS.md). That document tracks spec-vs-code
> reconciliation for the 30 V2 specification documents. This document
> tracks **functional gaps**, **ergonomic features**, and **new
> subsystems** that the code audit surfaced as necessary for
> production-ready operator deployments.
>
> **Relationship to V2_GAPS.md:** V2_GAPS.md is closed — every V2
> BLOCKER is resolved through V2.5. This document captures the
> *next* layer: things that must work for operators to run real
> workloads end-to-end.

---

## §1 — 🔴 Category 1: Functional Gaps (blocks real end-to-end usage)

These are code-verified gaps that prevent the kernel from executing
real agent workloads. The planner binaries, the dispatch loop, the
tool registries, the intent pipeline — all of that is implemented.
But two wiring gaps mean that no real agent work actually runs today.

### §1.1 — Planner task-prompt plumbing (FORWARD-ONLY, IMPLEMENTED)

**Severity:** 🔴 P0 — blocks all agent execution.
**Status:** ✅ **Implemented in V2.5** (forward-only — no scaffold-mode fallback).

**The problem.** The three planner role binaries (executor, reviewer,
orchestrator) have a full working agent loop
(`crates/planner-core/src/driver.rs::run_role_session`) that:

1. Parses the kernel-stamped env contract
   (`RAXIS_KERNEL_PLANNER_SOCKET`, `RAXIS_PLANNER_TASK_PROMPT`, etc.)
2. Builds the role-specific tool registry (executor: write tools;
   reviewer: read-only; orchestrator: DAG tools)
3. Constructs a `DispatchLoop` with the configured `ModelClient`
4. Renders the role-specific system prompt
5. Drives the loop to a terminal outcome
6. Converts the terminal tool into the matching IPC intent
   (`task_complete`, `submit_review`, `integration_merge`, etc.)
7. Returns a structured `DriverOutcome`

In V1 / V2.4-and-earlier the kernel never stamped
`RAXIS_PLANNER_TASK_PROMPT` into the guest env at spawn time, so
every spawned planner binary entered `DriverOutcome::Scaffold` and
parked on SIGTERM — **no real agent work ran**.

**Forward-only mandate.** Raxis V2.5 retired scaffold mode as a
production code path. There is no end user yet, so we move
features forward instead of carrying optional V1 plumbing
indefinitely. The new contract is:

* **Admission rejects empty descriptions.** The plan validator
  (`raxis-cli plan validate`) and the kernel's
  `parse_plan_tasks` / `parse_plan_orchestrator` reject any plan
  whose `[plan.initiative]` block or any `[[tasks]]` stanza is
  missing / empty / non-string / oversized `description` with
  `LifecycleError::PlanInvalid` ("`FAIL_PLAN_PARSE_ERROR`"),
  exactly the same severity as a missing `task_id`.
* **Stamping is unconditional.** Both spawn sites
  (`session_spawn_orchestrator::spawn_for_initiative` and
  `handlers::intent::handle_activate_sub_task` →
  `spawn_executor_for_task`) unconditionally populate
  `RAXIS_PLANNER_TASK_PROMPT` from the `PlanRegistry`'s
  `TaskPlanFields::description` /
  `OrchestratorPlanFields::description`. A
  `debug_assert!(!task_prompt.is_empty(), …)` guards both
  sites so a future regression in the parser surfaces loudly in
  test builds rather than silently spawning an idle agent.
* **Source of truth.** Orchestrator prompt comes from
  `[plan.initiative] description`; per-task prompts come from
  `[[tasks]] description`. Plan templates and scenario fixtures
  ship with concrete prompts — the migration removed every
  `[workspace] description` and every `context = …` field that
  pre-dated the canonical schema.

**Implementation surface (v2.5 → main).**

1. `kernel/src/initiatives/plan_registry.rs` —
   `TaskPlanFields::description` and
   `OrchestratorPlanFields::description` now non-optional fields
   on the registry, populated at `approve_plan` time.
2. `kernel/src/initiatives/lifecycle.rs::parse_plan_tasks` /
   `parse_plan_orchestrator` — extract + validate
   (trim trailing whitespace, 64 KiB cap, reject empty / wrong
   type).
3. `kernel/src/session_spawn_orchestrator.rs` —
   `pub const PLANNER_TASK_PROMPT_ENV` declared once;
   `spawn_for_initiative` stamps it unconditionally; trait doc
   pins the "always non-empty by construction" contract.
4. `kernel/src/handlers/intent.rs::handle_activate_sub_task` —
   builds `extra_env` with `RAXIS_PLANNER_TASK_PROMPT` from the
   plan registry's task fields.
5. `cli/src/commands/plan_validate.rs` — mirrors the kernel-side
   validation so operators see the rejection at `plan validate`
   time, before signing.
6. CLI templates (`cli/templates/plan_*.toml`) and scenario
   plans (`guides/scenarios/*/plan.toml`) ship with concrete,
   non-trivial multi-line descriptions for both
   `[plan.initiative]` and every `[[tasks]]`.

**Invariant safety.** The change preserves every prior invariant
and tightens one (`INV §1.1`: every spawned agent has a non-empty
seed prompt). There is intentionally no escape hatch — production
must move forward; legacy "park in scaffold mode" plans are
rejected at admission, not silently degraded at spawn.

---

### §1.2 — Integration merge host-side fast-forward (V2.5 SHIPPED — Phase 2 inline + §11 durable recovery)

**Status:** ✅ shipped — V2.5. Phase 2 (host-side fast-forward) is
wired AND the Phase 3 durable-recovery flag (`git_apply_pending`)
is fully implemented, including:

* DDL migration 16 adds `git_apply_pending INTEGER NOT NULL DEFAULT 0`
  to `initiatives` plus the partial index
  `idx_initiatives_pending_git`.
* Phase 1 sets the flag inside the same `BEGIN IMMEDIATE` block as
  the `current_sha` advance; Phase 3 clears it after a successful
  host-side merge.
* Pre-flight check rejects subsequent `IntegrationMerge` intents
  for the same initiative with `PlannerErrorCode::FailGitApplyPending`
  while the flag is set (no race window).
* Boot recovery (`kernel/src/recovery.rs::reconcile_git_apply_pending`,
  invoked from `main.rs` Step 8a after `KernelStarted` and before
  IPC accept) walks every flagged initiative and dispatches Cases
  A / B / C from [`integration-merge.md §11.3`](integration-merge.md), emitting one of
  `GitConsistencyRepaired` / `GitConsistencyVerified` /
  `GitStateInconsistent` per initiative.
* `IntegrationMergeCompleted` carries the fully-qualified
  `target_ref` so recovery does not need to re-resolve plan-fields.
* Worktree GC (`kernel/src/worktree_gc.rs::gc_session_worktree`)
  enforces `INV-MERGE-WORKTREE-RETAIN` (§11.4) via
  `raxis_store::views::sessions::pending_initiative_for_session`.
* Push handler waits for `git_apply_pending = 0` (§11.5) with a
  5 s deadline, emitting `PushFailed { category: "pending_git_apply" }`
  on timeout.

The `[ ]` checklist at the bottom of [`integration-merge.md §11`](integration-merge.md)
is now entirely `[x]`. There is no remaining V3 deferral on the
git-↔-SQLite transactional boundary.

**Forward-only mandate.** Per the V2 cleanup, there is no longer a
"backwards-compatibility audit-only path." Every successful
`IntegrationMerge` intent now drives the kernel through the
two-phase commit defined by [`integration-merge.md §11`](integration-merge.md):

* **Phase 1 (SQLite intent commit).** The kernel state machine is
  advanced and `IntegrationMergeCompleted` is emitted. (Same as
  before.)
* **Phase 2 (host-side fast-forward of the operator-configured
  `target_ref`).** Performed inline by the kernel, AFTER the SQLite
  commit and BEFORE the optional `auto_push`, by calling
  `raxis_domain_git::commit_merge_to_target_ref`. The function is
  idempotent on success; the operator-configured `target_ref` is
  resolved at admission time (`[workspace] target_ref` ⊕ `[git]
  default_target_ref` ⊕ `[git] target_ref_locked` ⊕ hardcoded
  `refs/heads/main`), stamped into `OrchestratorPlanFields`, and
  re-resolved against the *current* policy on kernel restart by
  `repopulate_plan_registry`.

**Implementation surface.**

* `kernel/src/handlers/intent.rs` — `run_phase_c` IntegrationMerge
  branch (after `tx.commit()`). Reads `target_ref` from
  `ctx.plan_registry.orchestrator(initiative_id).target_ref` and
  calls `commit_merge_to_target_ref` with the orchestrator
  `worktree_path` from `pre_state`.
* `kernel/src/initiatives/plan_registry.rs` — `OrchestratorPlanFields`
  carries `target_ref: String` (default `refs/heads/main`).
* `kernel/src/initiatives/lifecycle.rs` — `approve_plan` writes the
  resolved `target_ref` into the registry; `repopulate_plan_registry`
  re-resolves the plan's `target_ref` field against the current
  policy on kernel restart.
* `crates/audit/src/event.rs` — `MergeFastForwardFailed` audit
  variant (5 fields: `initiative_id`, `commit_sha`, `target_ref`,
  `category`, `reason`).
* `crates/domain-git/src/lib.rs` — `commit_merge_to_target_ref` is
  the existing host-side primitive (Phase 2a fetch + Phase 2b
  atomic ref update via `git update-ref`).

**Failure handling — `MergeFastForwardFailed`.** When Phase 2
fails, the kernel:

1. Logs the failure to stderr as a structured JSON line with
   `event = "IntegrationMergeFastForwardFailed"`.
2. Emits a typed `MergeFastForwardFailed` audit event carrying the
   `category` discriminator (`unopenable_main_repo`,
   `unopenable_source_repo`, `git_failed`, `missing_commit`,
   `target_ref_advanced_concurrently`, `invalid_sha`).
3. Suppresses the optional `auto_push` (pushing the un-advanced
   `target_ref` would race the operator's manual recovery).
4. Returns `IntentResponse::Accepted` for the Phase-1 intent — the
   merge commit IS recorded, the state machine IS advanced, and
   the audit chain has the durable signal an external auditor /
   operator dashboard / future recovery driver needs.

The full Phase-3 `git_apply_pending` durable-recovery flag is
tracked as a follow-up; the V2.5 cut performs Phase 2 inline and
relies on the audit-chain signal for operator recovery.

**Tests.**

* `kernel/tests/integration_merge_attribution_chain.rs::
  merge_fast_forward_failed_lands_on_audit_chain_with_category_discriminator`
  — pins the on-disk audit shape (real `FileAuditSink` +
  `AuditWriter`) and chain integrity.
* `crates/audit/src/event.rs` — `merge_fast_forward_failed_*`
  unit tests pin JSON round-trip + `as_str()` projection.
* `crates/domain-git/src/lib.rs` — full coverage of
  `commit_merge_to_target_ref` (idempotency, fetch, ref txn) is
  exercised by the existing `domain-git` integration test suite.

**Invariant safety.** The kernel never advances `current_sha`
past what the state machine committed; Phase 2 failure leaves the
initiative's `current_sha` at the orchestrator's claimed `head_sha`
in SQLite (the state machine already committed) but the
operator-configured `target_ref` lags. The `MergeFastForwardFailed`
audit row is the durable signal; the recovery driver re-runs
`commit_merge_to_target_ref` on next boot (the call is idempotent
on success).

---

## §2 — 🟡 Category 2: Operator-Facing Features (not blocking ship, high value)

### §2.1 — `SubscribeInitiative` (real-time initiative event stream) ✅ shipped (V2.5)

**Implementation.**

1. **Wire shape:** `raxis_types::InitiativeEvent` (
   `crates/types/src/initiative_event.rs`) — a `serde`-tagged
   enum carrying the operator-visible event payloads. The
   `kind` discriminator on the wire matches the variant name
   (`Subscribed`, `TaskStateChanged`, `InitiativeStateChanged`,
   `ReviewAggregationCompleted`, `EscalationRaised`,
   `EscalationResolved`, `IntegrationMergeCompleted`,
   `StructuredOutputEmitted`, `Closed`). `ClosedReason` enumerates
   the three terminal-frame causes (`InitiativeTerminal`,
   `KernelShutdown`, `InitiativeNotFound`).
2. **In-process bus:** `kernel::push::InitiativeEventBus`
   (`kernel/src/push/initiative_bus.rs`) — one
   `tokio::sync::broadcast::Sender<InitiativeEvent>` per
   initiative_id, allocated lazily on first publish/subscribe.
   Per-channel capacity is
   `PER_INITIATIVE_BROADCAST_CAPACITY = 256`; a slow operator
   that lags past the cap sees `Closed { reason: KernelShutdown }`
   and reconnects.
3. **Audit-tee:** `kernel::push::BroadcastingAuditSink` wraps
   the inbound `Arc<dyn AuditSink>` in `HandlerContext::new`.
   Every successful audit emit that carries an `initiative_id`
   AND maps to a public-wire variant (per
   `audit_kind_to_initiative_event`) is mirrored onto the bus
   AFTER the durable write. Failed emits never broadcast — the
   operator stream is a strict subset of the audit chain.
4. **Streaming dispatcher:** `ipc::operator::dispatch_loop`
   intercepts `OperatorRequest::SubscribeInitiative` BEFORE the
   per-request handler dispatch. It runs
   `validate_subscribe_admission` (initiative must exist + must
   not be terminal at attach time), then hands the
   `&mut UnixStream` to `stream_subscribe_initiative`, which
   subscribes to the bus, writes the
   `OperatorResponse::InitiativeSubscribed` ack as the first
   frame, then loops `bus.recv().await → write_json_frame_async`.
   The runner exits cleanly on
   `InitiativeStateChanged { to_state ∈ {Completed, Failed,
   Aborted} }` (writes `Closed { InitiativeTerminal }` and
   returns), on a peer disconnect (next write fails), or on a
   `Closed` channel.
5. **CLI:** `raxis initiative watch <initiative_id>`
   (`cli/src/commands/initiative.rs::run_watch`). Sends the
   request, asserts the ack envelope, then loops
   `OperatorConn::read_frame` and pretty-prints each event.
   Stops when the kernel writes the `Closed` frame.

**Estimate (delivered): ~660 lines** across `raxis-types`,
`kernel/src/push/initiative_bus.rs`, `ipc/operator_ergonomics.rs`,
`ipc/operator.rs`, `cli/src/commands/initiative.rs`,
`cli/src/conn.rs`, plus round-trip + integration tests.

**Tests.** `crates/types::initiative_event::tests` pin the wire
shape (10 round-trips covering every variant + variant-count
canary). `kernel::push::initiative_bus::tests` cover fan-out,
isolation across initiatives, the
"audit-emit-then-broadcast" ordering, and the
"do-not-broadcast-on-failed-emit" property.
`kernel::ipc::operator_ergonomics::stream_tests` cover the
end-to-end streaming flow against a `tokio::io::duplex` pair —
ack frame, two events, terminal `InitiativeStateChanged → Closed`,
and the `KernelShutdown` exit path.

---

### §2.2 — MongoDB SCRAM-SHA-256 (credential proxy auth) ✅ shipped (V2.5)

**Status:** ✅ Implemented. `credential-proxy-mongodb` now drives
SCRAM-SHA-256 SASL against the upstream when the credential URL
carries `user:pass@` userinfo. Production MongoDB 4.0+ deployments
are reachable through the proxy without the operator having to
configure `--noauth` on the upstream. The agent's view is unchanged
(no SASL on the agent side; `mount_as` URI is plain
`mongodb://127.0.0.1:PORT/db`).

**Implementation surface (v2.5 → main).**

1. `crates/credential-proxy-mongodb/src/upstream.rs` —
   * `ParsedUpstreamUrl` now retains `username`, `password`, and
     `auth_source` (parsed from the `authSource` query parameter,
     falling back to the path db, falling back to `"admin"`). The
     `has_userinfo()` method replaces the deprecated boolean field.
   * `scram_sha256_authenticate(stream, auth_source, user, password)`
     drives the full RFC 5802 + 7677 conversation:
       1. `saslStart` with `mechanism = SCRAM-SHA-256` and
          `client-first-message = "n,,n=<user>,r=<client-nonce>"`
          (24 random bytes, base64-encoded; well above the 16-bit
          minimum).
       2. Parse `server-first-message`: `r=<combined>,s=<base64-salt>,i=<iter>`.
          MUST verify (a) the combined nonce starts with the client
          nonce, (b) `iter ≥ 4096`, (c) no `m=<mandatory-extension>`.
       3. Compute
          `salted = PBKDF2-HMAC-SHA256(password, salt, iter, 32)`,
          `client_key = HMAC-SHA256(salted, "Client Key")`,
          `stored_key = SHA256(client_key)`,
          `server_key = HMAC-SHA256(salted, "Server Key")`.
       4. Send `saslContinue` with
          `client-final-message = "c=biws,r=<combined>,p=<base64(client_proof)>"`
          where `client_proof = client_key XOR HMAC-SHA256(stored_key, auth_message)`.
       5. Parse `server-final-message`: `v=<base64(server_signature)>`
          (success) or `e=<server-error>` (failure). MUST verify the
          server signature in **constant time** using
          `constant_time_eq`. Mismatch surfaces as
          `UpstreamError::AuthRejected("scram server-signature mismatch …")`.
       6. If neither the second nor third reply carries
          `done: true`, send a trailing empty `saslContinue` to let
          the server close the conversation.
   * `UpstreamError` gains an `AuthRejected(String)` variant that
     maps to audit reason `AuthRejected` per
     [`credential-proxy.md §14.5.3`](credential-proxy.md). Wrong-password / unknown-user /
     server-signature mismatch / RFC violation all surface as this.
2. `crates/credential-proxy-mongodb/src/wire.rs` — `BsonBuilder`
   gains `binary(key, bytes)` for BSON BinData subtype 0
   (the SASL `payload` field per the MongoDB driver spec).
3. `crates/credential-proxy-mongodb/Cargo.toml` adds workspace deps
   on `hmac`, `pbkdf2`, `base64`, and `getrandom`. The workspace
   pins `pbkdf2 = 0.12` (RustCrypto 0.10 family — same `Mac` trait
   surface as the existing `hmac` crate) and `base64 = 0.22`
   (the version `reqwest` already pulls in transitively, so no
   second base64 in the build graph).

**Tests.**

* Unit (RFC vectors):
  * `pbkdf2_hmac_sha256_matches_reference_vector`
    pins PBKDF2-HMAC-SHA256 against a known `{password, salt, 1, 32}`
    vector.
  * `hmac_sha256_matches_rfc4231_vector_1` pins HMAC-SHA-256 against
    RFC 4231 test vector 1 (`key = 20×0x0b`, `data = "Hi There"`).
  * `sha256_digest_of_empty_is_zero_hash` pins the empty-input
    SHA-256 against the canonical hex.
* Unit (RFC compliance):
  * `parse_server_first_message_extracts_r_s_i` /
    `parse_server_first_message_rejects_mandatory_extension` /
    `parse_server_first_message_rejects_missing_iter`.
  * `parse_server_final_message_returns_signature` /
    `parse_server_final_message_surfaces_server_error`.
  * `scram_username_escape_handles_reserved_chars` pins the RFC
    5802 §5.1 escaping (`,` → `=2C`, `=` → `=3D`).
  * `constant_time_eq_returns_true_on_equal` /
    `constant_time_eq_returns_false_on_diff_or_len`.
* Unit (state machine, end-to-end against in-process mock):
  * `scram_sha256_authenticate_against_mock_succeeds` drives the
    full state machine against an inline mock that validates the
    proxy's proof.
  * `scram_sha256_authenticate_wrong_password_is_auth_rejected`
    drives the same state machine with the wrong password and
    asserts `UpstreamError::AuthRejected` AND that the password
    bytes do not appear in the error message.
* Integration (real `MongodbProxy::serve` against a SCRAM-aware
  fake mongod fixture, `tests/proxy_upstream.rs`):
  * `scram_sha256_round_trips_against_real_upstream` proves the
    full path: SCRAM SASL → `UpstreamConnected` audit fires →
    agent's `find` round trips → upstream's `nReturned` flows back
    verbatim → `DatabaseQueryCompleted` audit fires.
  * `scram_sha256_with_wrong_password_surfaces_auth_rejected_audit`
    proves the SASL failure path: agent sees a synthesized
    `RaxisProxyError(8000)`, `CredentialProxyUpstreamFailed` audit
    classifies as `AuthRejected` (not `ProtocolHandshakeFailed`),
    and the password bytes never appear in the audit detail.

**Invariant safety.** Credential proxy is outside the kernel's
trust boundary, the agent never sees the upstream password, and the
SCRAM client uses `OsRng` for the client nonce so the conversation
is non-replayable. The constant-time server-signature comparison
prevents timing oracles. Restrictions still gate every command
post-handshake, so `allow_read_only` continues to refuse
`insert` / `update` / `delete` / `findAndModify` independently of
the auth path.

---

### §2.3 — MySQL `caching_sha2_password` (credential proxy auth) ✅ shipped (V2.5)

**Status:** ✅ Implemented. `credential-proxy-mysql` now negotiates
both `mysql_native_password` and `caching_sha2_password` on the
upstream side; operators no longer need to override
`default-authentication-plugin` on MySQL 8.0+ servers.

**Implementation surface (v2.5 → main).**

1. `crates/credential-proxy-mysql/src/upstream.rs` —
   * `caching_sha2_password_scramble(password, scramble) -> Vec<u8>`
     computes the 32-byte SHA-256 token
     (`SHA256(password) XOR SHA256(SHA256(SHA256(password)) || scramble)`).
   * `build_handshake_response_41` is now generic over the auth
     plugin and is dispatched via
     `build_handshake_response_41_native` /
     `build_handshake_response_41_sha256`.
   * `UpstreamSession::connect` inspects the server's advertised
     `auth_plugin_name` in HandshakeV10 and dispatches to either
     `handle_native_auth_result` (legacy 20-byte XOR token) or
     `drive_caching_sha2_auth` (32-byte SHA-256 token + state
     machine).
   * `drive_caching_sha2_auth` implements the full SHA-256 state
     machine:
       1. **Fast path:** server replies `0x01 0x03` → next packet
          MUST be `OK_Packet` (auth cache hit, no RSA needed).
       2. **Full auth path:** server replies `0x01 0x04` → proxy
          asks for the RSA public key (`0x02`), receives a
          PEM-encoded `RsaPublicKey`, XORs the cleartext password
          (with trailing NUL) against the scramble, and encrypts
          the result with `RSA-OAEP-SHA1`. The encrypted blob is
          sent as the next handshake packet.
       3. **Switch path:** the server can also issue an
          `AuthSwitchRequest` (`0xfe`) at any time; the proxy
          recomputes the SHA-256 token against the new scramble
          and reruns the state machine.
2. `crates/credential-proxy-mysql/Cargo.toml` adds the `rsa`
   dependency. The `sha1` and `sha2` crates were already in the
   workspace; both are reused here.
3. Module doc comments updated to describe the new wire shape and
   the explicit `OK_Packet` / `ERR_Packet` / `0x01 0x0?`
   classification used by `classify_terminal_auth_packet`.

**Tests.**

* `caching_sha2_scramble_is_deterministic_and_32_bytes` and
  `caching_sha2_scramble_matches_fixed_reference_vector` pin the
  deterministic SHA-256 contract.
* `caching_sha2_fast_path_completes_handshake` drives a
  hand-rolled TCP server that emits the real wire shape
  (HandshakeV10 → SHA-256 token validation → `0x01 0x03` fast
  success → `OK_Packet`). The proxy MUST complete the handshake
  with `handshake_ms < 5_000`.
* `caching_sha2_with_wrong_password_surfaces_auth_rejected`
  asserts the proxy maps an upstream `ERR_Packet` to
  `UpstreamError::AuthRejected` so the operator audit trail is
  the standard `AuthRejected` reason rather than a generic
  `ProtocolHandshakeFailed`.
* `caching_sha2_via_auth_switch_request_completes` exercises the
  AuthSwitchRequest mid-handshake path (server greets with
  `mysql_native_password` then switches to `caching_sha2_password`
  with a fresh scramble; the proxy MUST recompute the SHA-256
  token and complete).

**Invariant safety.** Unchanged from §2.2: credential proxy is
outside the kernel trust boundary, the agent never sees the
upstream password, and the proxy enforces deny-list +
read-/write-budget the same way for both auth plugins. RSA-OAEP
encryption uses `OsRng` so the encrypted blob is non-replayable.

---

### §2.4 — In-VM KSB (Kernel State Block) renderer (V2.5 IMPLEMENTED)

**Status:** ✅ Implemented in V2.5 (`raxis-ksb` shared crate +
kernel-side assembly + driver-side fold).

**Implementation surface (v2.5 → main).**

1. `crates/ksb/` — new workspace crate that owns `KsbSnapshot`,
   `DagRow`, `ReviewerVerdict`, `PendingEscalation`, `CredentialPort`,
   the `KSB_DELIMITER_OPEN` / `KSB_DELIMITER_CLOSE` /
   `PLANNER_KSB_ENV` / `KSB_SCHEMA_VERSION` constants, the
   `render_ksb` deterministic renderer, and `assemble_system_prompt`.
   The planner crate re-exports the canonical types directly from
   `raxis-ksb` (`pub use raxis_ksb::{...}` in
   `crates/planner-core/src/lib.rs`).
2. `kernel/src/initiatives/ksb_assembly.rs` — projects live state
   (initiative + task rows, `PlanRegistry`, escalations) into a
   `KsbSnapshot`. Provides `fallback_snapshot` so transient SQLite
   contention never blocks initiative activation.
3. `kernel/src/session_spawn_orchestrator.rs` — both
   `spawn_orchestrator_for_initiative` and `spawn_executor_for_task`
   call `assemble_ksb_snapshot` (off the tokio worker via
   `spawn_blocking`), serialize to JSON, and stamp into the guest env
   as `RAXIS_PLANNER_KSB`. `LiveOrchestratorSpawn::new` takes
   `Arc<PlanRegistry>` so the spawn path can read plan-side fields.
4. `crates/planner-core/src/driver.rs` —
   `run_role_session_with_env_fn` reads `RAXIS_PLANNER_KSB`,
   deserializes to `Option<KsbSnapshot>`, and feeds
   `run_role_session_with_model`. The system prompt is built via
   `raxis_ksb::assemble_system_prompt(NNSP, snap)` when present; the
   NNSP-only path remains for unit tests that pass `None`.

**Tests.** `raxis-ksb` ships 21 unit tests (deterministic render,
delimiter sanitization, JSON round-trip, field-order stability).
`planner-core::driver` adds two new tests pinning the KSB-fold
contract (`run_role_session_with_model_folds_ksb_snapshot_into_system_prompt`
and `run_role_session_with_model_uses_nnsp_only_when_no_ksb_supplied`).
Kernel binary tests (750) and integration tests stay green.

**Invariant safety.** Unchanged from §2.4 invariant note above:
KSB is read-only, stamped into the guest env at spawn time, and the
agent cannot modify it.

#### V2.6 extension — role-scoped capabilities envelope

Slice C (commit landing alongside this note) extends the KSB
projection with a role-scoped capabilities envelope. The envelope
surfaces the kernel-side admit-predicate verdicts to the LLM so
the planner can pre-evaluate inadmissible intents BEFORE
submitting them — the iter44 leading-indicator metric
`IntentAdmitPredicateEvaluatedTotal{admissible="false"}` measures
the rate of LLM blind-asks; the envelope is the structural
mitigation that drives that rate toward zero.

Three invariants pin the contract:

1. `INV-KSB-CAPABILITIES-PARITY-01`. The envelope's
   `retry_admissible` boolean is computed from
   `raxis_types::intent_admit::admit_retry_subtask_check` — the
   SAME pub fn the `RetrySubTask` IPC handler runs. Same inputs ⇒
   same answer. The IPC handler keeps its eprintln /
   observability emission per rejection branch; the predicate
   owns the boolean decision only.
2. `INV-KSB-CAPABILITIES-ROLE-SCOPED-01`. The envelope is a Rust
   enum with three disjoint variants (`Orchestrator`, `Executor`,
   `Reviewer`); the type system prevents an executor's KSB from
   carrying the orchestrator's per-initiative respawn counter or
   peer-task review trajectories. The reviewer's variant is
   identity-only (`session` + `artifact_task_id`) — counters MUST
   NOT appear; the reviewer's verdict is on the artifact, not on
   the executor's prior trajectory.
3. `INV-KSB-CAPABILITIES-TURN-COHERENT-01`. `assemble_capabilities`
   reads from the SAME `&Connection` `assemble_ksb_snapshot`
   uses for the rest of the projection, inheriting SQLite's
   per-connection read-consistency model.

Implementation surface:

  * `crates/types/src/intent_admit.rs` — the shared predicate +
    structured outcome (`AdmitOutcome` /
    `RetryInadmissibleReason`). Pure function — takes primitives,
    returns primitives, no I/O.
  * `crates/ksb/src/lib.rs` — `Capabilities` enum +
    `OrchestratorCapabilities` / `ExecutorCapabilities` /
    `ReviewerCapabilities` + `SessionCapabilityView` /
    `InitiativeCapabilityView` / `TaskCapabilityView` types;
    extended `KsbSnapshot` with `Option<Capabilities>` field
    (additive, non-breaking); renderer extension for the
    `capabilities=` block.
  * `kernel/src/handlers/intent.rs::handle_retry_sub_task` —
    routes its eligibility cascade through
    `raxis_types::intent_admit::admit_retry_subtask_check`; each
    rejection branch keeps its eprintln / observability emit so
    dashboards stay byte-stable.
  * `kernel/src/initiatives/ksb_assembly.rs::assemble_capabilities`
    — per-role envelope construction with single-`&Connection`
    reads (turn-coherent contract).
  * `crates/planner-core/src/driver.rs` — orchestrator NNSP
    extended with rule 3a guidance to consult the
    `capabilities=` block BEFORE issuing `retry_subtask`.
  * `kernel/tests/ksb_capabilities_parity.rs`,
    `kernel/tests/ksb_capabilities_role_scoped.rs`,
    `kernel/tests/ksb_capabilities_turn_coherent.rs` — three
    witness tests pinning the three invariants.

#### V2.7 extension — `planner_max_turns` on `SessionCapabilityView`

V2.7 (`INV-KSB-MAX-TURNS-VISIBILITY-01`) extends
`SessionCapabilityView` with one new `pub planner_max_turns: u32`
field. The same value is also stamped into the spawned VM's env
under `RAXIS_PLANNER_MAX_TURNS`; both surfaces share a single call
to
`kernel/src/session_spawn_orchestrator.rs::resolve_planner_max_turns_for`,
so they are bit-equal by construction.

The renderer
(`crates/ksb/src/lib.rs::push_session_capability_line`) emits the
`planner_max_turns=N` token uniformly on the `role=…` line for
ALL three role envelopes:

```text
capabilities=
  role=orchestrator session=<id> planner_max_turns=N
  initiative=<…>
  tasks=
    - task=<…> crash=<n>/<m> review=<n>/<m> retry_admissible=<…>
```

Why surface this on the KSB rather than only via the env var: the
in-VM agent (LLM) does not have direct visibility into its own
process env — it only sees the rendered system prompt the driver
assembles. Surfacing `planner_max_turns` on the per-session
capabilities line lets the renderer expose the budget verbatim. The
agent then self-tracks its own turn count by counting prior
assistant turns in its own conversation transcript and computes
`remaining = planner_max_turns - turn_index` accordingly. The role
NNSPs instruct the agent on how to use the remaining budget (e.g.
the Executor at >75% spent should prefer `task_complete` over
speculative further investigation).

The resolver precedence chain itself
(`INV-PLANNER-MAX-TURNS-PRECEDENCE-01`) is documented in
[`v2-deep-spec.md §Step 12`](v2-deep-spec.md) and `guides/recipes/env/11-planner-env-vars.md`.

**Original problem statement (preserved for context).** The planner's
system prompt was previously a hardcoded string template in
`crates/planner-core/src/driver.rs:400-422`. It said "you are the
executor for task X of initiative Y" but contained no live kernel
state.

**What KSB is.** The Kernel State Block is a structured JSON
document the kernel assembles at session activation time, containing:

* Initiative metadata (id, state, target_ref, policy_epoch)
* Task DAG snapshot (which tasks are done, which are blocked,
  which are running, predecessor/successor relationships)
* Reviewer verdicts on prior attempts (approved/rejected + critique)
* Escalation state (any pending escalations the operator must
  resolve)
* Credential proxy port assignments (which ports map to which
  upstream services)
* Path scope (which files this task is allowed to touch)
* Budget state (tokens consumed so far, ceiling)

**Why it matters.** Without KSB, the agent has no context about the
broader initiative. The executor doesn't know what other tasks have
done, what the reviewer said about the last attempt, or what files
it's allowed to touch. It operates on the task prompt alone.

**What's needed.**

1. **KSB assembly in the kernel.** A function that reads the
   initiative state, task states, reviewer verdicts, escalation
   rows, and credential port assignments from the store and
   assembles a `KsbDocument` struct. ~200 lines.
2. **KSB serialization.** Render the `KsbDocument` to a
   structured text block suitable for inclusion in the system
   prompt. ~50 lines.
3. **KSB injection at spawn time.** Stamp the rendered KSB into
   `extra_env["RAXIS_PLANNER_KSB"]` alongside
   `RAXIS_PLANNER_TASK_PROMPT`. The driver reads it and prepends
   it to the system prompt. ~30 lines.
4. **Driver-side rendering.** `render_system_prompt_for_role`
   reads `RAXIS_PLANNER_KSB` from the env and inserts it after
   the role blurb. ~20 lines.

**Estimate:** ~300 lines.

**Invariant safety:** KSB is read-only kernel state rendered at
spawn time. It does not mutate any rows, does not bypass admission,
and does not introduce a new IPC surface. The agent cannot modify
the KSB — it is stamped into the guest env before the process
starts. `INV-OPERATOR-ERG-01` (read-only handlers) is satisfied
trivially because KSB assembly is not a handler.

---

### §2.5 — Token-limit enforcement (per-provider pricing)

**Current state:** The `EstimateCost` handler uses a flat heuristic
rate (`$0.01 / 1K tokens`). The kernel tracks `actual_cost` on
the task row but has no per-provider pricing tables. There is no
mid-session budget enforcement — the dispatch loop runs to
completion regardless of spend.

**What's needed.**

1. **Policy schema expansion.** Add `[providers.<id>.pricing]`
   tables to `policy.toml`:

   ```toml
   [providers.anthropic.pricing]
   input_tokens_per_dollar  = 200_000   # $5 / 1M input
   output_tokens_per_dollar = 50_000    # $20 / 1M output
   ```

   Parsed into `ProviderPricing` on `PolicyBundle`. ~60 lines.

2. **Real-time token counting.** The dispatch loop already tracks
   `Usage { input_tokens, output_tokens }` per response. Wire
   the cumulative counts into the `IntentSubmitter` so the kernel
   receives actual token usage with every intent. ~30 lines.

3. **Budget enforcer.** At intent admission, the kernel computes
   the dollar cost from the provider's pricing table and the
   reported token counts, compares against
   `policy.max_cost_per_task`, and rejects if exceeded. ~80 lines.

4. **Mid-session abort.** The dispatch loop checks cumulative
   tokens against a ceiling (from `DispatchConfig`) after each
   model response. `DispatchOutcome::TokensExceeded` is already
   implemented — just needs the ceiling wired from the kernel's
   budget response. ~40 lines.

**Estimate:** ~210 lines.

**Invariant safety:** Budget enforcement is fail-closed — exceeding
the ceiling rejects the intent. No new trust surface; the pricing
tables are operator-declared in policy (same trust model as
`max_cost_per_task`).

---

### §2.6 — Sidecar streaming + heartbeat ✅ shipped (V2.5)

**Status.** ✅ Implemented in V2.5
(`crates/planner-core/src/sidecar_client.rs` +
`crates/planner-core/src/streaming.rs` +
[`extensibility-traits.md §9A.5A`](extensibility-traits.md)).

**What shipped.**

1. **Per-chunk idle timeout (heartbeat detection).** Every chunk
   read on the sidecar SSE stream is wrapped in
   `tokio::time::timeout(DEFAULT_STREAM_IDLE_TIMEOUT, …)` (30 s
   default).  Silences beyond that surface a synthesised terminal
   `StreamEvent::Stop { stop_reason: "stream_idle_timeout_after_30_s" }`
   and the underlying TCP connection is dropped.  Sidecars SHOULD
   emit `: heartbeat\n\n` SSE comment lines during idle; those are
   skipped by `SseParser` and reset the idle deadline by virtue of
   being a chunk read.

2. **Reconnect logic.** Lives in the existing
   `RetryingModelClient`
   (`crates/planner-core/src/retry.rs`) — a transport-class error
   from `create_message_stream` is retryable per `is_retryable`,
   so the retry shell re-issues the full request against the same
   sidecar (or falls through to the next provider via
   `FallbackModelClient`).  This matches
   [`provider-failure-handling.md §7.5`](provider-failure-handling.md)'s "no resumable streams"
   stance.

3. **Mid-stream budget abort.** Already shipped via
   `DispatchLoop::run_streaming`
   (`crates/planner-core/src/dispatch.rs`).  The dispatch loop
   monitors `StreamEvent::Usage` events and drops the receiver
   when a configured ceiling is hit.  The sidecar reader task
   observes `tx.send(...).is_err()`, bails, and the underlying
   TCP connection is severed so the sidecar stops generating
   tokens promptly.

**Wire shape.** New `POST <endpoint>/v1/stream` endpoint on the
sidecar — request shape and HMAC headers identical to
`/v1/complete`; response is `text/event-stream` with the eight
event kinds documented in [`extensibility-traits.md §9A.5A`](extensibility-traits.md).  The
terminal `complete` event carries an HMAC-SHA256 signature over
`<request_id>:<timestamp_ms>:<canonical_json(response)>` so the
planner can verify provenance end-to-end without per-event
signing (the only bytes the dispatch loop ever feeds into
`INV-PROVIDER-04` are the aggregated `MessageResponse` in
`StreamEvent::Complete`).

**Tests** (in `crates/planner-core/src/sidecar_client.rs`):

* `stream_happy_path_against_local_sidecar_server` — full
  round-trip against a local TCP server: planner stamps HMAC,
  server emits 8 events, planner aggregator yields matching
  `StreamEvent`s and surfaces a `MessageResponse` identical to the
  buffered path.
* `stream_passes_through_heartbeat_comments` — `: heartbeat`
  comment lines are skipped without producing extra events.
* `stream_with_bogus_complete_signature_surfaces_aggregator_error`
  — wrong-secret sidecar surfaces a terminal `Stop` and never
  yields `StreamEvent::Complete`.
* `stream_eof_without_complete_surfaces_terminal_stop` — early
  EOF surfaces a `Stop { stop_reason: "stream_eof_before_complete" }`.
* `stream_pre_stream_4xx_surfaces_upstream_error` — non-2xx
  responses surface synchronously, never as a torn channel.
* `hmac_sha256_helper_round_trips_against_compute_hmac` — pins
  the canonicalisation helper used by the aggregator.
* `constant_time_eq_returns_correct_value` — pins the timing-safe
  comparator used in signature verification.

**Invariant safety.** The sidecar runs outside the kernel trust
boundary ([`extensibility-traits.md §9A.6`](extensibility-traits.md)).  The streaming path
preserves every invariant the buffered path satisfies:

* `INV-PROVIDER-04` (atomic per-turn delivery) — the dispatch
  loop's tool-execution path consumes only the terminal
  `StreamEvent::Complete`; intermediate events are
  observability-only.  Same shape as
  `AnthropicClient::create_message_stream`.
* `R-3` (Fail-closed) — signature mismatch / malformed JSON /
  bind-check failure all surface as terminal `Stop` events; the
  receiver closes without yielding a `Complete`.
* `R-5` (Bounded capabilities) — token usage from
  `StreamEvent::Usage` feeds the dispatch loop's cumulative
  ceilings (V2_GAPS §C1); ceiling breaches cause
  `run_streaming` to drop the receiver mid-stream, severing the
  upstream connection.
* `R-7` (Audit chain) — kernel-side audit is unchanged; the
  streaming wire shape is a planner→sidecar concern only.

---

## §3 — 🟢 Category 3: New Planner Tools

### §3.1 — `Sleep` (token-budget-preserving wait)

**What it does.** Lets an agent wait for an external process (CI
build, database migration, deployment rollout) without burning
model turns on a polling loop.

```json
{
  "tool": "sleep",
  "input": { "seconds": 15, "reason": "waiting for CI to finish" }
}
```

The dispatch loop calls `tokio::time::sleep(duration)` and resumes
without consuming a model inference turn. One `Sleep(15)` costs
zero tokens vs. a `bash("while ! curl ...; do true; done")` loop
that costs thousands.

**Policy guardrails required.**

1. **`policy.max_sleep_seconds`** — hard ceiling per call (e.g.,
   60). The tool rejects any `seconds > max_sleep_seconds` with
   a structured error. Prevents an agent from stalling a VM for
   hours.
2. **Cumulative sleep budget.** The dispatch loop tracks total
   sleep time. When cumulative sleep exceeds
   `policy.max_cumulative_sleep_seconds` (e.g., 300), the next
   `Sleep` call fails with `FAIL_SLEEP_BUDGET_EXCEEDED`.
3. **Wall-clock accounting.** Sleep time counts against the
   session's wall-clock budget (if configured) so a sleeping agent
   still eventually times out.

**Implementation.**

1. **Tool definition.** Add `sleep` to the executor tool registry
   (`crates/planner-core/src/tools.rs`). Input schema:
   `{ seconds: u32, reason?: string }`. ~40 lines.
2. **Dispatch integration.** The `DispatchLoop` handles `sleep`
   as a non-model tool call: sleep the duration, return
   `{ "slept_seconds": N }` as the tool result, resume without
   incrementing the turn counter. ~30 lines.
3. **Policy wiring.** Read `max_sleep_seconds` and
   `max_cumulative_sleep_seconds` from `DispatchConfig` (populated
   from the kernel's session env). ~20 lines.

**Estimate:** ~90 lines.

**Invariant safety.**

* `INV-PLANNER-HARNESS-04` (turn ceiling) — Sleep does not
  increment the turn counter, which is correct because no model
  inference occurs. The wall-clock budget is the backstop.
* `INV-CAPACITY-01` (VM slot) — Sleep holds the VM slot. The
  cumulative sleep budget prevents indefinite slot hold.
* Reviewer tool registry — `Sleep` is **not** added to the
  reviewer registry. The Pure-Static Reviewer has no external
  process to wait for (`INV-PLANNER-HARNESS-02`).

---

### §3.2 — `StructuredOutput` (typed mid-session communication)

**What it does.** Lets an agent emit structured data mid-session
that the kernel can validate, store, and surface to operators or
downstream agents. Unlike terminal tools (which end the session),
`StructuredOutput` is a **non-terminal** tool — the session
continues after the output is emitted.

**Design: fixed enum, not open-ended JSON.**

The kernel defines a closed set of output kinds. This is consistent
with the RAXIS invariant model: the kernel is a reference monitor
that structurally validates every IPC payload. Open-ended JSON
would create an unvalidatable surface.

> [!IMPORTANT]
> **Invariant review checkpoint.** Before implementing
> `StructuredOutput`, the following invariants MUST be reviewed to
> ensure the new tool does not create a bypass:
>
> * `R-1` (Domain separation) — structured output must not leak
>   cross-initiative state. Each output is scoped to the emitting
>   session's `(initiative_id, task_id)`.
> * `R-2` (Mediated I/O) — the output is submitted through the
>   kernel UDS, not written to a shared filesystem. The kernel
>   validates the payload before storing it.
> * `R-5` (Bounded capabilities) — the output tool is a capability
>   the kernel grants. It must be revocable (omit from tool registry
>   → agent cannot emit).
> * `R-10` (Opaque rejection) — if the kernel rejects an output
>   (malformed, rate-limited, unknown kind), the error message must
>   not leak internal kernel state.
> * `INV-PLANNER-HARNESS-02` — Reviewer must NOT have the
>   `structured_output` tool. Reviewer verdicts go through
>   `submit_review` exclusively.
> * `INV-PLANNER-HARNESS-04` — StructuredOutput IS a model turn
>   (the model chose to call the tool). It MUST increment the turn
>   counter.
> * `INV-OPERATOR-ERG-01` — Reading stored outputs via the CLI is a
>   read-only operation. The handler must not mutate kernel state.

**Output kind enum (Rust):**

> [!IMPORTANT]
> **Wire shape (INV-IPC-BINCODE).** The enum uses the **default
> external-tag** serde representation (NOT
> `#[serde(tag = "kind")]` as an earlier draft suggested). The
> canonical IPC encoder is `bincode::serde` which does NOT
> support `serde::deserialize_any` and rejects internally-tagged
> enums with `Decode(Serde(AnyNotSupported))`. The
> snake-case `kind` discriminator the model and CLI speak is
> bridged to the external-tag wire shape by the
> `parse_structured_output_input` helper in
> `crates/planner-core/src/tools.rs` and surfaced for SQL
> projections via `StructuredOutputKind::variant_tag()`.

```rust
/// Typed mid-session output kinds. Each variant has a fixed schema
/// the kernel validates before accepting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StructuredOutputKind {
    /// Mid-session progress snapshot. The kernel stores it as an
    /// audit event; the operator dashboard (§4) renders it as a
    /// progress bar / file list.
    ProgressReport {
        files_modified: Vec<String>,
        tests_passing:  u32,
        tests_failing:  u32,
        confidence:     f32,  // 0.0–1.0, clamped at validation
    },

    /// "I found something the operator should see." The kernel
    /// stores it and optionally routes it through the notification
    /// system (§notification-routing.md). Critical-severity flags
    /// can trigger an escalation.
    DiagnosticFlag {
        severity: DiagnosticSeverity,  // Info | Warning | Critical
        message:  String,              // ≤ 1024 chars, validated
        evidence: Option<String>,      // file path or line ref
    },

    /// Executor → Orchestrator handoff. Stored on the task row so
    /// the orchestrator's KSB (§2.4) includes it when activating
    /// the next task.
    TaskSummary {
        commit_sha:    String,
        changed_paths: Vec<String>,
        approach:      String,  // ≤ 2048 chars, one-paragraph rationale
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticSeverity {
    Info,
    Warning,
    Critical,
}
```

**Tool input schema (JSON, exposed to the model):**

```json
{
  "name": "structured_output",
  "description": "Emit a typed mid-session output. Use progress_report for status updates, diagnostic_flag for operator alerts, task_summary for handoff to the orchestrator.",
  "input_schema": {
    "type": "object",
    "required": ["kind"],
    "properties": {
      "kind": { "enum": ["progress_report", "diagnostic_flag", "task_summary"] },
      "files_modified": { "type": "array", "items": { "type": "string" } },
      "tests_passing":  { "type": "integer" },
      "tests_failing":  { "type": "integer" },
      "confidence":     { "type": "number", "minimum": 0, "maximum": 1 },
      "severity":       { "enum": ["info", "warning", "critical"] },
      "message":        { "type": "string", "maxLength": 1024 },
      "evidence":       { "type": "string" },
      "commit_sha":     { "type": "string" },
      "changed_paths":  { "type": "array", "items": { "type": "string" } },
      "approach":       { "type": "string", "maxLength": 2048 }
    }
  }
}
```

**Implementation status: ✅ shipped (V2.5).**

1. **Types.** `StructuredOutputKind` + `DiagnosticSeverity` in
   `crates/types/src/structured_output.rs`. External-tag serde
   enum (see Wire shape note above) with `validate_and_normalise`
   (clamp confidence, truncate over-cap strings, reject non-hex
   `commit_sha`) + size constants
   (`STRUCTURED_OUTPUT_MAX_DIAG_MESSAGE_BYTES`,
   `STRUCTURED_OUTPUT_MAX_APPROACH_BYTES`,
   `STRUCTURED_OUTPUT_MAX_PATH_LIST_LEN`,
   `STRUCTURED_OUTPUT_MAX_PATH_BYTES`,
   `STRUCTURED_OUTPUT_PER_SESSION_RATE_LIMIT`).
2. **Tool handler.** `StructuredOutputTool` in
   `crates/planner-core/src/tools.rs` registered into
   `build_executor_registry_full` /
   `build_orchestrator_registry_full` (NOT reviewer — pinned by
   `reviewer_registry_never_includes_structured_output` test).
   Parses snake-case input → bridges to external-tag wire enum →
   submits via `IntentSubmitter::submit_structured_output`.
3. **Kernel IPC handler.** `IntentKind::StructuredOutput` arm in
   `kernel/src/handlers/intent.rs::run_phase_a` dispatches to
   `handle_structured_output` (validate → rate-limit COUNT +
   INSERT in one BEGIN IMMEDIATE tx → `StructuredOutputEmitted`
   audit emit → NON-TERMINAL Accepted response). The handler
   does NOT auto-escalate `DiagnosticFlag { severity: Critical }`
   in V2.5 — operator dashboards are the routing surface; an
   auto-escalation would be a policy decision (the kernel is the
   reference monitor, not the policy engine).
4. **Store.** Migration 13 creates `structured_outputs`:
   `(output_id, initiative_id, task_id, session_id, kind,
   severity, payload_json, emitted_at)`. Indexes on
   `(task_id, emitted_at)`, `(initiative_id, emitted_at)`,
   `(session_id)` so the CLI / dashboard read paths and the
   per-session rate-limit COUNT all run as index probes.
5. **CLI.** `raxis task outputs <task-id>` exposed by
   `cli/src/commands/task_outputs.rs`. Read-only.

**Rate limiting.** The kernel enforces
`STRUCTURED_OUTPUT_PER_SESSION_RATE_LIMIT` (currently 10) outputs
per session. Exceeding the limit returns
`FAIL_STRUCTURED_OUTPUT_RATE_LIMITED`. The COUNT + INSERT run
inside one `BEGIN IMMEDIATE` so concurrent submissions on the
same session cannot race past the cap.

---

## §4 — 🔵 Category 4: Operator Dashboard (HTTP backend + React UI)

### §4.1 — Overview

The operator dashboard is a **read-only web UI** that gives
operators real-time visibility into the kernel's state. It replaces
the need to run multiple CLI commands to understand what the kernel
is doing.

**Design principles:**

1. **Read-only.** The dashboard never mutates kernel state. All
   data comes from read-only SQLite connections
   (`SQLITE_OPEN_READ_ONLY`) and in-memory bounded queues. This
   is consistent with `INV-OPERATOR-ERG-01`.
2. **Operator-scoped.** Every view is scoped by the authenticated
   operator's role. An operator with `read` permission sees state;
   an operator with `write` permission can additionally view and
   edit `policy.toml` in the browser.
3. **Kernel-launched.** The HTTP server starts when the kernel
   starts (configurable via `policy.toml`). No separate process
   to manage.
4. **Fast.** React frontend with client-side rendering. The
   backend serves a static bundle + JSON API endpoints. No SSR,
   no framework overhead.

### §4.2 — Authentication (challenge-response with signed keys)

**Authentication flow.** The dashboard uses the same operator
key infrastructure (`raxis-crypto`) that the CLI uses. No
passwords, no sessions cookies with secrets — cryptographic
identity only.

1. **Browser requests challenge.** `GET /api/auth/challenge`
   returns a JSON object:
   ```json
   {
     "challenge": "<random-32-byte-hex>",
     "expires_at": 1715300000
   }
   ```
   The challenge is valid for 60 seconds. The kernel stores it
   in a bounded in-memory map (max 100 pending challenges; oldest
   evicted on overflow).

2. **Operator signs the challenge outside the browser.** The
   dashboard displays the challenge hex and a copyable CLI command.
   The operator runs `raxis auth sign <challenge>` on their local
   machine (where their private key resides) or uses a hardware
   token. The CLI outputs the Ed25519 signature and public key.
   The operator pastes **only the signature and public key**
   (both non-secret) back into the browser:
   ```text
   POST /api/auth/verify
   {
     "challenge": "<the-challenge>",
     "signature": "<ed25519-sig-hex>",
     "public_key": "<operator-pubkey-hex>"
   }
   ```

   > **Security invariant.** The operator's private key MUST NEVER
   > enter browser memory. Previous implementations that prompted
   > the operator to paste their private key into a `<textarea>`
   > and signed via WebCrypto were removed because:
   > (a) the key sat in a React `useState` string, readable by XSS
   > payloads or browser extensions; (b) the paste wrote to OS
   > clipboard history; (c) JavaScript provides no memory-zeroing;
   > (d) the `CryptoKey` was imported with `extractable: true`,
   > allowing re-export by any script on the page.

3. **Kernel verifies.** The kernel:
   * Checks the challenge exists and is not expired.
   * Verifies the Ed25519 signature.
   * Looks up the public key in the `operator_keys` table.
   * Checks the operator's certificate status via
     `CertEnforcer::enforce` (same path as CLI auth).
   * Returns a JWT (24 hour TTL by default, HS256 with a kernel-
     generated ephemeral secret rotated at boot — see
     [`dashboard-hardening.md §2.8`](dashboard-hardening.md) and
     `INV-DASHBOARD-AUTOLOGIN-VALID-AT-BOOT-01`; the per-boot
     secret regeneration still invalidates every token the
     instant the kernel exits):
     ```json
     {
       "token": "<jwt>",
       "operator_id": "alice",
       "roles": ["read", "write_policy"],
       "expires_at": 1715303600
     }
     ```

4. **Browser stores the JWT** in `localStorage` and sends it as
   `Authorization: Bearer <jwt>` on every API request.

5. **Logout.** `POST /api/auth/logout` — the kernel adds the JWT
   to a bounded revocation set (max 1000 entries; entries expire
   naturally). The browser clears `localStorage`.

**Roles.**

| Role | Permissions |
|---|---|
| `read` | View all dashboard pages (initiatives, tasks, DAG, sessions, audit, escalations, git worktrees, diffs, structured outputs, agent streams) |
| `write_policy` | Additionally: view and edit `policy.toml` in the browser, trigger policy reload |
| `admin` | Additionally: view operator keys, view certificate status, trigger `raxis doctor` from dashboard |

Roles are derived from the operator's certificate attributes
(same source as CLI permission checks). No separate role table.

### §4.3 — HTTP backend (Rust, kernel-integrated)

**Architecture.** The dashboard backend is a new crate
`raxis-dashboard` that the kernel binary links. It is NOT a
separate process — it shares the kernel's `Store` (read-only
connections) and `HandlerContext` (for policy snapshot, plan
registry, notification router).

**Server stack:**

* `axum` (already in the workspace via `gateway`) for HTTP routing
* `tower-http` for CORS, static file serving, compression
* `tokio` for async (already the kernel's runtime)

**Startup.** Configured in `policy.toml`:

```toml
[dashboard]
enabled       = true
bind_address  = "127.0.0.1"
bind_port     = 9820
# Optional: serve over TLS with the kernel's certificate.
tls_cert_path = ""
tls_key_path  = ""
```

The kernel starts the dashboard server in `kernel/src/main.rs`
after the store is initialized and the policy is loaded. A
disabled dashboard (`enabled = false`) has zero runtime cost.

**API endpoints (JSON):**

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/auth/challenge` | Issue a challenge for login |
| `POST` | `/api/auth/verify` | Verify signed challenge, return JWT |
| `POST` | `/api/auth/logout` | Revoke JWT |
| `GET` | `/api/initiatives` | List all initiatives with state summary |
| `GET` | `/api/initiatives/:id` | Initiative detail (state, metadata, task count) |
| `GET` | `/api/initiatives/:id/dag` | Task DAG as adjacency list with state per node |
| `GET` | `/api/initiatives/:id/tasks` | All tasks for an initiative |
| `GET` | `/api/tasks/:id` | Task detail (state, session, reviewer verdicts, structured outputs) |
| `GET` | `/api/tasks/:id/outputs` | Structured outputs for a task |
| `GET` | `/api/sessions` | List active and recent sessions |
| `GET` | `/api/sessions/:id` | Session detail (agent type, state, token usage) |
| `GET` | `/api/sessions/:id/stream` | SSE stream of raw model output (bounded in-memory queue) |
| `GET` | `/api/escalations` | List pending escalations |
| `GET` | `/api/escalations/:id` | Escalation detail |
| `GET` | `/api/audit` | Paginated audit chain (newest first) |
| `GET` | `/api/audit?initiative_id=X` | Filtered audit events |
| `GET` | `/api/inbox` | Operator inbox (pending actions) |
| `GET` | `/api/health` | Kernel health state (doctor summary) |
| `GET` | `/api/policy` | Current policy snapshot (read role) |
| `GET` | `/api/policy/toml` | Raw `policy.toml` content (write_policy role) |
| `PUT` | `/api/policy/toml` | Update `policy.toml` + trigger reload (write_policy role) |
| `GET` | `/api/git/worktrees` | List worktrees (main + per-executor/orchestrator) |
| `GET` | `/api/git/worktrees/:name` | Worktree detail (HEAD, branch, status) |
| `GET` | `/api/git/worktrees/:name/log` | Git log (last N commits) |
| `GET` | `/api/git/worktrees/:name/diff` | Diff between worktree HEAD and main |
| `GET` | `/api/git/worktrees/:name/diff/:sha1..:sha2` | Diff between two commits |
| `GET` | `/api/plan/:initiative_id` | Rendered plan TOML for an initiative |
| `GET` | `/api/vm-images` | Operator-published `[[vm_images]]` registry |

**Agent stream capture.** Raw model streaming output (the SSE
chunks the gateway relays from the model provider) is not stored
in `kernel.db` (it would be too large and too transient). Instead:

1. **Bounded file ring.** Each active session's raw model output
   is appended to `<data_dir>/streams/<session_id>.jsonl`. Each
   line is a timestamped SSE event. Max file size: 10 MB per
   session (configurable). On overflow, the oldest lines are
   truncated (ring buffer semantics via `seek + truncate`).
2. **In-memory tail.** The dashboard backend holds the last 500
   events per active session in a `tokio::sync::broadcast` channel.
   The `/api/sessions/:id/stream` SSE endpoint taps this channel
   for real-time streaming to the browser.
3. **Persistence across restart.** On kernel restart, the
   `.jsonl` files survive. The dashboard loads the last N lines
   from disk for sessions that were active at shutdown. The
   in-memory broadcast is refilled from the file tail.

### §4.4 — React frontend (✅ shipped — V2.5)

**Layout.** The frontend lives at `raxis/dashboard-fe/`. It is
NOT a workspace member of the Rust workspace; the Rust dashboard
crate consumes the *built bundle* (`dashboard-fe/dist/`) at
runtime via `tower_http::services::ServeDir`. The path is
configured by `[dashboard] static_dir` in `policy.toml`:

```toml
[dashboard]
enabled    = true
bind_port  = 9820
# Absolute or operator-cwd-relative path to the built bundle.
static_dir = "/srv/raxis/dashboard-fe/dist"
```

When `static_dir` is set, ServeDir is mounted as the router's
fallback service so any non-`/api/*` path serves the bundle's
`index.html`, enabling SPA client-side routing (deep links like
`/initiatives/init-abc/dag` resolve in the browser).

**Stack (final).**

* React 18 + TypeScript (strict; `noUnusedLocals`, `noUnusedParameters`)
* Vite 6 for build tooling (`tsc -b && vite build`); JS chunks
  split into `react`, `query`, `monaco`, `dagre`, `index` for
  cache stability. (Bumped from Vite 5 in 2026-05 to take the
  GHSA-4w7w-66w2-5vf9 / CVE-2026-39365 path-traversal patch in
  vite ≥ 6.4.2; vitest was bumped 2.x → 3.x in lockstep because
  vitest 3 is the first line that supports vite 6.)
* React Router 6 (`BrowserRouter`)
* `@tanstack/react-query` 5 for data fetching, caching, and
  background refetch
* `dagre` for DAG layout (rendered as SVG inline — no canvas
  WebGL dependency); Recharts is intentionally NOT used
  (SVG-DAG is the only graph surface, and Recharts ships ~50 KB
  for one bar-chart that the operator dashboard does not need)
* `@monaco-editor/react` for the `policy.toml` editor
  (lazy-loaded by Vite chunk-split; only fetched when the
  policy page mounts)
* Tailwind CSS 3 with a custom dark-first operator palette
  (`ink`, `panel`, `edge`, `accent`, plus state-tone families
  `ok`, `warn`, `bad`, `info`, `block` mirroring kernel FSM
  vocabulary)
* `react-diff-viewer-continued` is intentionally NOT used —
  the DiffView component is implemented from scratch as a
  hunk-line renderer keyed off the kernel's already-clamped
  64 KiB-per-file unified diff payload, which keeps the bundle
  small and avoids one more transitive dep tree

**Cross-tab auth.**
* JWT lives in `localStorage` under `raxis.dashboard.token.v1`,
  profile under `raxis.dashboard.profile.v1`. A `storage` event
  listener in `Shell.tsx` re-reads on cross-tab logout.
* `RequireAuth` route guard checks token TTL (with a 30-second
  buffer) and redirects unauthenticated requests to
  `/login?next=<path>` so the post-login redirect lands the
  operator on the page they originally requested.
* The `Authorization: Bearer <jwt>` header is auto-injected by
  the `apiFetch` wrapper. The SSE endpoint accepts the JWT via
  `?token=<jwt>` query string as a fallback (see §4.5: the
  browser EventSource API does not allow custom headers).

**CLI-mediated Ed25519 signing.** Login uses a strict
challenge-response flow that NEVER lets the operator's
private key enter the browser. The dashboard:

1. Calls `GET /api/auth/challenge` and renders the 32-byte
   hex challenge with a copy button + a one-shot copyable
   command line: `raxis auth sign --json <challenge-hex>`.
2. The operator runs that command in their terminal (the
   CLI loads the operator key via `--operator-key <path>`
   or `RAXIS_OPERATOR_KEY` env var, signs the bytes with
   Ed25519, and prints `{challenge, public_key, signature}`
   as JSON or human-readable lines).
3. The operator pastes the public key + signature back into
   the dashboard form. The dashboard POSTs them, alongside
   the original challenge, to `/api/auth/verify`.

**Why CLI-mediated and NOT in-browser.** The earlier draft
of this spec proposed in-browser WebCrypto signing of the
challenge after the operator pasted their private key. That
design was implemented and then reverted in commit `a78ef45`
for these reasons:

* **XSS pivot risk.** Any XSS in the dashboard would let an
  attacker exfiltrate the typed key BEFORE the WebCrypto
  call, regardless of CSP.
* **Clipboard / IME history.** Pasting a key into a browser
  text input writes it to clipboard managers, IME caches,
  and sometimes shoulder-surfable history rings. None of
  those exist for a CLI subprocess.
* **No memory zeroing.** The browser's GC does not zero the
  string buffer holding the typed key; a subsequent process
  dump (or browser extension) can recover it. The CLI
  zeroes its key buffer on drop.
* **Policy clarity.** The kernel already requires the
  operator key for every other privileged action (plan
  signing, policy advancement, etc). Reusing the same key
  flow for dashboard login means the operator does not have
  to manage a "browser key" distinct from their CLI key.

The shipped `src/lib/ed25519.ts` therefore contains ONLY
the security rationale — there is no in-browser signing
code anywhere in the bundle.

**Build artifact.**
```text
dist/
├── index.html
├── raxis-logo.svg
└── assets/
    ├── index-<hash>.{js,css}
    ├── react-<hash>.js
    ├── query-<hash>.js
    ├── monaco-<hash>.js
    └── dagre-<hash>.js
```
Total gzipped: ~125 KB JS + ~5 KB CSS at first paint, well
under the operator dashboard target of 200 KB. The
`real_bundle_serving.rs` integration test points the
dashboard at `dashboard-fe/dist/` and asserts that
`GET /` serves the real Vite-emitted `index.html`, asset
chunks load with the right content-type, deep SPA links
fall through to `index.html`, and `/api/*` routes never
fall through to ServeDir.

**Pages.**

| Route | Page | Description |
|---|---|---|
| `/login` | Login | Challenge-response auth flow |
| `/` | Home / Overview | Kernel health, active initiative count, recent activity feed, resource utilization |
| `/initiatives` | Initiative List | Sortable/filterable table of all initiatives with state badges, task progress bars, created/updated timestamps |
| `/initiatives/:id` | Initiative Detail | Full initiative view with embedded DAG, task list, escalation summary, timeline |
| `/initiatives/:id/dag` | DAG View | Interactive directed acyclic graph visualization. Nodes = tasks, colored by state (green=completed, blue=running, gray=pending, red=failed, yellow=blocked). Click a node → task detail panel slides in. |
| `/initiatives/:id/plan` | Plan View | Rendered `plan.toml` with syntax highlighting. Shows `[workspace]`, `[[tasks]]`, `[orchestrator]` sections. |
| `/tasks/:id` | Task Detail | State machine history, session list, reviewer verdicts with critique text, structured outputs timeline, path scope visualization |
| `/sessions/:id` | Session Detail | Agent type, model id, token usage chart (input/output over turns), tool call log, terminal outcome |
| `/sessions/:id/stream` | Agent Stream | Real-time raw model output. SSE-connected, auto-scrolling terminal-style view. Shows tool calls inline with syntax-highlighted JSON. Paused sessions show the persisted `.jsonl` tail. |
| `/escalations` | Escalations | Pending escalation list with initiative context, severity, requested action |
| `/inbox` | Operator Inbox | Unified view of pending actions: escalations to resolve, reviews to acknowledge, initiatives awaiting operator input |
| `/audit` | Audit Chain | Paginated, filterable audit event log. Each event expandable to show full payload. Filter by initiative, task, event kind, time range. |
| `/git` | Git Worktrees | List of worktrees: `main`, each executor's branch, orchestrator's integration branch. Select any to see log + diff. |
| `/git/:worktree` | Worktree Detail | Git log (commit list), file tree at HEAD, unified diff vs. main. Side-by-side diff view option. |
| `/git/:worktree/diff/:sha1..:sha2` | Diff View | Full diff between two commits. Syntax-highlighted, file-by-file, with expand/collapse. |
| `/policy` | Policy View | Read-only rendered `policy.toml` (read role). Monaco editor with save button (write_policy role). Diff against previous epoch on save. |
| `/health` | Health | `raxis doctor` output rendered as a checklist. Green/yellow/red per category. Auto-refreshes every 30 seconds. |
| `/vm-images` | VM Images | Operator-published `[[vm_images]]` registry. Per-entry: alias, digest, role restriction, Linux kernel floor, cache status. |

**UI design principles:**

1. **Dark mode default.** Operator tooling runs in terminals and
   dark IDEs. The dashboard matches that context. Light mode toggle
   available.
2. **Information density.** Operators need to see a lot of state
   at once. Dense tables, compact cards, collapsible sections.
   No wasted whitespace.
3. **Real-time indicators.** Pulsing dots on running sessions,
   live token counters, auto-updating DAG colors. SSE connections
   for agent streams and initiative events.
4. **Keyboard navigation.** `j/k` for list navigation, `Enter`
   to drill in, `Escape` to go back. Vim-style for operators who
   live in the terminal.
5. **Fast.** Static bundle served by axum. API responses are JSON
   with `Cache-Control: no-cache` for live data. React Query
   handles background refetch (5-second stale time for list
   endpoints, 1-second for detail endpoints with active sessions).
6. **Responsive but desktop-first.** Operators use this on
   widescreen monitors. The layout is optimized for ≥ 1440px but
   degrades gracefully to 1024px. Mobile is not a target.

### §4.5 — Read/write role enforcement

**Read role (default).** Every API endpoint except
`PUT /api/policy/toml` is read-only. The JWT carries the
operator's roles; the middleware checks `roles.contains("read")`
for all `GET` endpoints.

**Write policy role (✅ shipped — V2.5).** `PUT /api/policy/toml`
requires `roles.contains("write_policy")` (granted to
operators with `RotateEpoch` in their cert's `permitted_ops`).
The endpoint mirrors the CLI flow `raxis policy reload
--policy <toml> --sig <sig>`: the operator must supply BOTH a
new policy.toml AND a detached Ed25519 signature over those
exact bytes, signed by the authority key. **The dashboard
NEVER holds the authority private key** — the operator signs
offline (e.g. on an air-gapped workstation) and pastes the
detached signature into the editor.

**Wire shape.**

```http
PUT /api/policy/toml
Authorization: Bearer <jwt>
Content-Type: application/json

{
  "toml":          "<full UTF-8 TOML content>",
  "signature_b64": "<base64 of 64 raw Ed25519 signature bytes>"
}

→ 200
{
  "previous_epoch":              7,
  "new_epoch":                   8,
  "policy_sha256":               "abcd…(64 hex chars)",
  "signed_by_authority":         "f1f1…(16 hex chars)",
  "n_sessions_invalidated":      3,
  "n_delegations_marked_stale":  2,
  "advanced_at":                 1730000123
}
```

The handler:

1. Validates JWT + role + JSON body shape; rejects empty TOML
   and signatures whose decoded length ≠ 64 with HTTP 400
   (`FAIL_DASHBOARD_BAD_REQUEST`). Accepts both padded and
   unpadded base64 (operator-friendly copy/paste behaviour).
2. Hands off to the kernel-resident `KernelPolicyAdvancer`
   inside `tokio::task::spawn_blocking` (the advance path
   touches SQLite + the file system).
3. The advancer atomically stages the new bytes onto the
   canonical `policy.toml` / `policy.toml.sig` paths via
   `<path>.dashboard.tmp` + `rename`. On any failure
   (signature invalid, replay, malformed TOML, IO trouble) it
   restores the previous bytes so a partial write never
   leaves the canonical files inconsistent with the in-memory
   `Arc<ArcSwap<PolicyBundle>>`.
4. Calls `policy_manager::advance_epoch` — the same pipeline
   the operator IPC `RotateEpoch` handler uses. This emits
   `PolicyEpochAdvanced` and updates the in-memory swap.
5. Emits `AuditEventKind::PolicyUpdatedViaDashboard` with
   the operator's pubkey fingerprint, the previous epoch,
   the new epoch, and the policy SHA-256. This is in
   ADDITION to the canonical `PolicyEpochAdvanced` so an
   auditor can distinguish dashboard-driven advances from
   CLI-driven advances at a glance.
6. Returns the structured `PolicyAdvancement` envelope.

**Failure mapping.**

| Status | Code | Trigger |
|---|---|---|
| 400 | `FAIL_DASHBOARD_BAD_REQUEST` | empty TOML, malformed base64, signature ≠ 64 bytes |
| 400 | `FAIL_DASHBOARD_POLICY_INVALID` | signature mismatch / replay / malformed TOML |
| 401 | `FAIL_DASHBOARD_AUTH_*` | missing / invalid / revoked JWT |
| 403 | `FAIL_DASHBOARD_FORBIDDEN` | operator lacks `write_policy` role |
| 500 | `FAIL_DASHBOARD_INTERNAL` | IO trouble persisting / rolling back |

**Architecture seam.** The dashboard crate (`raxis-dashboard`)
defines an `update_policy_toml` method on the `DashboardData`
trait. Production wiring lives in `raxis-dashboard-kernel`
(`KernelDashboardData::update_policy_toml`) which delegates to
a `PolicyAdvancer` trait object. The kernel binary supplies
the production impl (`KernelPolicyAdvancer` in
`kernel/src/dashboard_glue.rs`) which holds Arc handles for
the `KeyRegistry`, `Store`, `AuditSink`,
`Arc<ArcSwap<PolicyBundle>>`, `EpochBinding`, and the optional
`ArtifactStore`. Tests use a `ClosurePolicyAdvancer`
(also in `raxis-dashboard-kernel`) so the HTTP route layer
can be exercised without booting the full kernel.

**Admin role.** `GET /api/health` (doctor output) requires
`roles.contains("admin")`. Operator key listing and certificate
status are admin-only because they contain security-sensitive
metadata.

### §4.6 — Implementation plan

| Phase | Scope | Estimate | Status |
|---|---|---|---|
| 1 | `raxis-dashboard` crate skeleton + axum server + static serving + auth endpoints | ~400 lines | ✅ shipped |
| 2 | Core API endpoints (initiatives, tasks, sessions, audit, escalations, inbox) | ~600 lines | ✅ shipped |
| 3 | Git worktree API (log, diff, file tree) | ~300 lines | ✅ shipped |
| 4 | Agent stream capture (bounded file ring + broadcast channel + SSE endpoint) | ~250 lines | ✅ shipped |
| 5 | Policy view/edit API + `PolicyUpdatedViaDashboard` audit | ~250 lines | ✅ shipped |
| 6 | React frontend: scaffold + routing + auth flow + overview page | ~800 lines | ✅ shipped |
| 7 | React frontend: initiative detail + DAG visualization + task detail | ~1000 lines | ✅ shipped |
| 8 | React frontend: session detail + agent stream view | ~600 lines | ✅ shipped |
| 9 | React frontend: git worktree + diff view + audit log | ~800 lines | ✅ shipped |
| 10 | React frontend: policy editor + health page + inbox + notifications | ~500 lines | ✅ shipped |
| **Total** | | **~5500 lines** | ✅ shipped |

### §4.7 — Invariant safety

The dashboard introduces a new network-facing surface (HTTP server).
The following invariants must be reviewed:

* **`R-1` (Domain separation).** The dashboard runs in the kernel
  process, not inside a VM. It has read-only access to the store.
  It cannot inject intents, spawn sessions, or mutate task state.
  The only write path is `PUT /api/policy/toml`, which goes
  through the same validation as the CLI's `raxis policy reload`.

* **`R-2` (Mediated I/O).** The dashboard's HTTP listener is
  bound to a configurable address (default `127.0.0.1` — loopback
  only). Exposing it to a network requires explicit operator
  configuration in `policy.toml`.

* **`R-10` (Opaque rejection).** API errors must not leak internal
  kernel state. Error responses use the same `FAIL_*` code
  vocabulary as the operator UDS, with no stack traces or internal
  paths in production mode.

* **`INV-CERT-01` (certificate mandatory).** The JWT is derived
  from a certificate-verified operator key. Expired / revoked
  certificates cannot obtain a JWT. The JWT itself has a 1-hour
  TTL and is revocable via logout.

* **`INV-OPERATOR-ERG-01` (read-only handlers).** Every `GET`
  handler is a pure read from the store or in-memory state. The
  `PUT /api/policy/toml` handler is the only write, and it
  delegates to the kernel's existing policy reload path which is
  already audited.

---

## §5 — Priority Summary

| Priority | §  | Item | Est. lines |
|---|---|---|---|
| 🟢 DONE | §1.1 | Plan `description` REQUIRED + `RAXIS_PLANNER_TASK_PROMPT` unconditional stamp | ~50 |
| 🟢 DONE | §1.2 | Integration merge Phase 2 (host-side fast-forward) inline + `MergeFastForwardFailed` audit | ~140 |
| 🟢 DONE | §2.1 | `SubscribeInitiative` real-time stream (operator UDS streaming + broadcast tap) | ~80 |
| 🟢 DONE | §2.4 | In-VM KSB renderer (`raxis-ksb` + kernel assembly + driver fold) | ~300 |
| 🟢 DONE | §2.5 | Token-limit enforcement (`request_token_budget` + `TokenBudgetExhausted`) | ~210 |
| 🟢 DONE | §2.6 | Sidecar streaming + heartbeat + reconnect + mid-stream budget abort | ~180 |
| 🟢 DONE | §2.2 | MongoDB SCRAM-SHA-256 (RFC 5802 + 7677 + AuthSource) | ~400 |
| 🟢 DONE | §2.3 | MySQL `caching_sha2_password` (fast-path + RSA-OAEP full-auth + AuthSwitchRequest) | ~140 |
| 🟢 DONE | §3.1 | `Sleep` tool | ~90 |
| 🟢 DONE | §3.2 | `StructuredOutput` (fixed enum + `task outputs` CLI) | ~310 |
| 🟢 DONE | §4   | Operator dashboard — backend ✅ shipped (P1-P5) + React FE ✅ shipped (P6-P10, ~3700 LOC under `raxis/dashboard-fe/`) | 0 |
| | | **Total remaining** | **0** |
