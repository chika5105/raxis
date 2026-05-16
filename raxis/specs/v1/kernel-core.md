# RAXIS — Part 2 (Core): Kernel Binary Specification

> **Scope:** `raxis-kernel` — source tree layout (Part 2.1), startup sequence and IPC server (Part 2.2), internal subsystem specifications (Part 2.3), and the Initiative/Task FSMs (Part 2.4). Full function signatures for all subsystem boundaries.
>
> **Supersession:** §2.5.8 in [Part 2 Store](kernel-store.md) is normative over any conflicting prose here (particularly `vcs/diff.rs` diff command and `handlers/intent.rs` step ordering).
>
> **Navigation:** [README](../../README.md) | [Part 1](philosophy.md) | [Part 2 Store](kernel-store.md) | [Part 3](peripherals.md)

---

> The file inventories above cover foundational workspace scaffolding and shared library crates only.
> Component-level file inventories (every source file in each binary, with rationale) are in Parts 2–4.
> Part 2 covers the kernel binary in file-level detail.
> Part 3 covers the planner, gateway, and verifier binaries.
> Part 4 covers the CLI, test suites, genesis ceremony, and policy fixtures.

---

### Part 2 — The Kernel Binary (`raxis-kernel`)

> Part 2 is written in five sub-parts.
> Part 2.1 covers the kernel file tree and `Cargo.toml` only — the authoritative module layout. The startup sequence is in Part 2.2.
> Part 2.2 covers the startup sequence, `main.rs`, `bootstrap.rs`, `recovery.rs`, `errors.rs`, and the full IPC server subsystem.
> Part 2.3 covers authority, scheduler, gates, provider routing, prompt, policy manager, and break-glass — with full function signatures for all subsystem boundaries.
> Part 2.4 covers the Initiative and Task FSMs (Gap 4), DAG execution mechanics, `initiatives/` handler specs, recovery, and trust invariants INV-INIT-01..09.
> Part 2.5 (§2.5.1 complete; §2.5.2–§2.5.7 planned) covers the store DDL and isolation model, plan artifact signing contract, key inventory, operator CLI authentication, and [[gates]] normative schema — closing the remaining Part 2 gaps before Part 3.

The kernel is the authority core. It is the only process that reads the signed policy store, holds provider credentials, writes to the kernel state database, and appends authority-class audit events. Everything else — planner, gateway, verifier — communicates through typed, authenticated IPC and has no direct access to any of those resources.

**The kernel's hard constraint: stable, reproducible behavior given recorded inputs.** The kernel's outputs must be derivable from: the state store, the audit log, and the sequence of IPC inputs — all of which are recorded. Sources of non-determinism that are explicitly permitted and always logged: wall-clock timestamps (kernel-owned, logged in every audit event and proof record), OS-assigned PIDs (auxiliary metadata only, never used for cryptographic binding). Sources that are forbidden without logging: any external state read not reflected in the audit record, any ordering decision based on filesystem traversal order without a stable sort applied on top.

---

#### Part 2.1 — Kernel Source Tree and `Cargo.toml`

Every subsystem is its own Rust module. This is not cosmetic — it enforces that each subsystem's internal state and functions are inaccessible to sibling subsystems unless explicitly re-exported. The `gates` module never imports `raxis-store` directly; each `gates/` submodule uses only the facades permitted by the boundary rule (see **`gates` subsystem boundary rule** below). This prevents accidental cross-subsystem coupling and keeps every submodule independently unit-testable.

```text
kernel/
├── Cargo.toml
└── src/
    ├── main.rs                        # entry point; startup sequencer
    ├── bootstrap.rs                   # genesis state machine; fail-closed boot
    ├── recovery.rs                    # post-crash reconciliation
    ├── policy_manager.rs              # epoch advance; policy reload; delegation sweep
    ├── breakglass.rs                  # one-time recovery credential; dual audit write
    ├── errors.rs                      # BOOT_ERR_* exit codes + typed KernelError enum
    ├── witness_index.rs               # sole module for store witness rows + blobs (read AND write); both gates/witness.rs (lookup) and ipc/handlers/witness.rs (ingest verifier writeback) go through this facade — no other module holds a store reference for witness operations
    │
    ├── vcs/
    │   ├── mod.rs
    │   └── diff.rs                    # resolve range (base_sha, head_sha) → sorted touched path list (INV-07 input); v1: git CLI subprocess (deterministic stdout, no libgit2 C binding risk)
    │
    ├── ipc/
    │   ├── mod.rs                     # wires listener + auth + dispatcher
    │   ├── listener.rs                # UDS accept loop; per-connection task spawn
    │   ├── auth.rs                    # token + sequence + nonce validation (INV-01)
    │   ├── dispatcher.rs              # typed IpcMessage routing to handlers; maps internal errors to coarse planner-facing codes (INV-08)
    │   └── handlers/
    │       ├── mod.rs
    │       ├── intent.rs              # handles IntentRequest from planner
    │       ├── fetch.rs               # handles FetchRequest; allowlist + audit (INV-02B)
    │       ├── witness.rs             # handles WitnessSubmission from verifier
    │       ├── escalation.rs          # handles EscalationRequest from planner; ApprovalToken verify; ApprovalProof issuance (Gap 3)
    │       └── proposal_append.rs     # accepts ProposalEvent only; no authority-class append
    │
    ├── authority/
    │   ├── mod.rs                     # re-exports: session, delegation (check_capability, record_capability_use, list_delegations, mark_stale_on_epoch_advance), verifier_token, keys, approval
    │   ├── session.rs                 # session create/revoke; token issuance (INV-01)
    │   ├── delegation.rs              # delegation issuance; TTL; two-phase staleness (StaleOnNextUse → RenewalRequired)
    │   ├── verifier_token.rs          # single-use verifier run tokens; issue / validate / consume
    │   ├── keys.rs                    # holds live key material; HMAC and Ed25519 sign/verify primitives only — policy artifact verification is orchestrated by bootstrap.rs and policy_manager.rs, not here
    │   └── approval.rs                # approval token verify; proof record; consume (INV-06)
    │
    ├── scheduler/
    │   ├── mod.rs                     # re-exports: admit, dag (next_ready_tasks, mark_task_complete, transition_to_admitted), lane, budget
    │   ├── admit.rs                   # task row insert + DAG edge insert (approve_plan path only; no budget check, no initial_state arg — see Part 2.3 amendment)
    │   ├── dag.rs                     # predecessor tracking; next_ready_tasks; transition_to_admitted
    │   ├── lane.rs                    # lane admission; fairness accounting
    │   └── budget.rs                  # pre-call admission; post-call reconciliation (INV-02A)
    │
    ├── gates/
    │   ├── mod.rs                     # evaluate_claims; sole call site for record_capability_use (step 4 terminal Pass)
    │   ├── claim.rs                   # per-claim delegation + submission + scope check; returns ClaimCheckResult (INV-07)
    │   ├── witness.rs                 # witness index lookup via witness_index facade (INV-03); no direct store import
    │   ├── verifier_runner.rs         # spawn verifier; issue run token; global concurrent cap + pending queue
    │   └── policy_lookup.rs           # claim-requirement table query; required_claims → Vec<ClaimType>; StrictDefault handling
    │
    ├── provider/
    │   ├── mod.rs                     # ProviderCtx { policy, store, gateway_channel, audit }; re-exports execute_fetch, check_rate_limit, check (allowlist)
    │   ├── fetch.rs                   # execute_fetch method on ProviderCtx; allowlist → gateway → audit → rate record
    │   ├── allowlist.rs               # domain allowlist enforcement for FetchRequest (INV-02B)
    │   ├── gateway.rs                 # GatewayChannel; forward_fetch to gateway subprocess over dedicated UDS
    │   ├── rate_limit.rs              # per-session fetch quota; check_rate_limit / record_fetch (reads session.fetch_quota from store)
    │   └── audit_egress.rs            # write_fetch_audit; audit-before-release invariant (INV-02B)
    │
    ├── prompt/
    │   ├── mod.rs
    │   ├── assembler.rs               # assemble(session_id, ctx) → AssembledPrompt; epoch-bound; no cache
    │   └── epoch_binding.rs           # session_prompt_valid; invalidate_session_prompts on epoch advance
    │
    └── initiatives/                   # Gap 4: Initiative + Task FSM; all initiative/task lifecycle operations
        ├── mod.rs                     # re-exports lifecycle, task_transitions, recovery
        ├── lifecycle.rs               # create_initiative, approve_plan, evaluate_terminal_criteria, abort_initiative
        ├── task_transitions.rs        # transition_task, TransitionActor; single call-site for evaluate_terminal_criteria
        └── recovery.rs                # reconcile_tasks (called by recovery::reconcile); resume_task
```

**Total: 49 source files + `Cargo.toml`** (root: 7, vcs: 2, ipc: 10, authority: 6, scheduler: 5, gates: 5, provider: 6, prompt: 3, initiatives: 4 — 7+2+10+6+5+5+6+3+4 = 48, plus `Cargo.toml` = 49). This tree is the authoritative file layout. Part 2.3 is the authoritative contract for the function signatures, invariants, and internal structure of all files up to and including `breakglass.rs`. Part 2.4 (§4.6) is the authoritative contract for `src/initiatives/`. Any discrepancy between this tree and Part 2.3/2.4 is a specification error in the tree — Parts 2.3 and 2.4 win.

**INV-08 placement note:** `policy_lookup.rs` returns opaque result types (`ClaimCheckResult`, not string reason codes). `dispatcher.rs` is the only layer that maps internal typed errors to planner-facing response codes (`FAIL_MISSING_WITNESS`, `FAIL_POLICY_VIOLATION`, etc.) — no other module may construct a planner-facing error string directly. This is the rule that enforces INV-08: a single serialization point where expansion to coarse codes is deliberate and reviewable, not scattered across handlers. `ipc/auth.rs` owns INV-01 (token/sequence/nonce rejection before dispatch); `dispatcher.rs` owns INV-08 (coarse code mapping after handler execution).

**`vcs/diff.rs` role in INV-07:** `gates/claim.rs` cannot derive required claims on its own — it needs the set of paths actually touched across the intent's commit range. `vcs/diff.rs` resolves `(base_sha, head_sha)` from the planner's intent (already validated as full SHAs) to a sorted, stable list of touched paths, which `claim.rs` passes to `policy_lookup.rs`. The planner-submitted path manifest is explicitly discarded at this stage — only VCS-derived paths feed the lookup.

**`epoch_binding.rs` / `policy_manager.rs` coordination:** When `policy_manager.rs` advances the epoch, it (1) marks active delegations stale-on-next-use in the store, and (2) notifies `prompt::epoch_binding` to mark all existing assembled prompts as epoch-invalid. On the next planner inference request, the assembler detects the invalid epoch flag, reassembles under the new epoch, and logs the reassembly event. Planner sessions do not need to reconnect; only the static prompt scaffold portion is rebuilt.

**`gates` subsystem boundary rule:** The `gates` module must not import `raxis-store` directly and must not reach into internal types of the `authority` module. Each `gates/` submodule may only reach the outside world through typed kernel-internal facades (never `raxis-store` directly). The permitted facades and the specific file that uses each are:

- **`gates/claim.rs`** — composes three facades: `authority` (delegation check), `policy` (claim-requirement table), and `vcs` (touched-path diff). All three are kernel-local modules; none exposes raw store rows. (Illustrative signatures: `authority::delegation::check_capability(session_id, capability_class) -> DelegationStatus`; `policy::claim_table::required_claims(paths) -> Vec<ClaimType>`; `vcs::diff::touched_paths(base_sha, head_sha, worktree_root) -> Vec<PathBuf>` — exact paths locked in Part 2.3.)
- **`gates/witness.rs`** — uses `witness_index` only (read-side lookup). Obtains `Option<WitnessRecord>` by `(evaluation_sha, task_id, gate_type, verifier_run_id)`. `evaluation_sha` is the `head_commit_sha` of the range intent the gate is being evaluated for — same field name as in `WitnessRecord` and `AuditEventKind::WitnessAccepted`. No authority, policy, or vcs import.
- **`gates/verifier_runner.rs`** — uses `authority` (to issue a `verifier_run_token` for the spawned verifier process) and kernel IPC spawn helpers (to fork the verifier subprocess with resource caps and the token). Does not call `witness_index`, `policy`, `vcs`, or `store` directly; the witness writeback arrives separately through `ipc/handlers/witness.rs`. (Full spawn interface in Part 2.3.)
- **`gates/policy_lookup.rs`** — uses `policy` only (claim-requirement table query). Returns `ClaimCheckResult` structured types; no string codes, no authority or store import.

This design keeps every `gates/` file testable in isolation: tests substitute stub implementations of `authority`, `policy`, `vcs`, `witness_index`, and IPC spawn helpers without spinning up a real SQLite store or subprocess. Full function signatures for all facades are in Part 2.3.

---

##### `kernel/Cargo.toml` — [NEW]

**Why it matters beyond build configuration:** The kernel's `Cargo.toml` is itself a trust surface. Any dependency added here potentially expands the kernel's attack surface or pulls in capability that violates the thin-kernel principle. Every dependency must be justified; unjustified additions are a code-review defect.

Key decisions encoded in this file:

- **`edition = "2021"`, `resolver = "2"`** — required for correct feature unification across the workspace. Without resolver v2, a feature enabled by one crate can silently activate it in another, potentially enabling HTTP client code in the kernel through a transitive feature flag.
- **`tokio` with explicit feature list**: `features = ["rt", "net", "sync", "time", "macros"]`. This is a declaration of intent; the actual enforcement is the `cargo deny` allowlist below.
- **HTTP stack denylist via `cargo deny`**: The workspace `deny.toml` bans HTTP client crates (`hyper`, `reqwest`, `ureq`, `h2`, and equivalents) scoped to `raxis-kernel` only — not a global workspace ban, since the gateway binary legitimately needs HTTP. The exact `deny.toml` syntax (whether `[[bans]]` entries, `wrappers`, `skip`, or `skip-tree`) should be confirmed against the cargo-deny version in use at implementation time; the intent is a kernel-scoped ban enforced by `cargo deny check bans` in CI, not by `cargo tree | grep`.
- **`raxis-types`, `raxis-crypto`, `raxis-ipc`, `raxis-policy`, `raxis-audit-tools`, `raxis-store`** — the six workspace crates the kernel links. This list is the machine-readable statement of the kernel's authority surface. Adding a seventh entry here (e.g., `raxis-audit-tools-writer`) would be a mistake — the kernel uses `audit-tools`, which has the full chain-write capability.
- **`rusqlite` with `bundled` feature** — SQLite bundled to avoid version skew with the host OS. WAL mode and `synchronous = FULL` are set at runtime in `store/src/db.rs`, not compile-time.
- **`ed25519-dalek`** (or `ring`) — signing backend for token and policy artifact verification. Version is pinned; updates require explicit review because a signing library regression is a security event.
- **`[profile.release]`**: `panic = "abort"`, `opt-level = 3`, `debug = false`. Abort on panic ensures no unwinding in production; unwinding in a kernel process can leave shared state partially mutated.

> **End of Part 2.1.**
> Part 2.1 is the kernel module layout only. It does not specify startup sequence (Part 2.2), subsystem function signatures (Part 2.3), or initiative handler internals (Part 2.4 §4.6).
> Part 2.2 covers the startup sequence, `main.rs`, `bootstrap.rs`, `recovery.rs`, `errors.rs`, and the full IPC server subsystem (including `vcs/diff.rs`, `handlers/escalation.rs`, and the renamed `proposal_append.rs`).

---

#### Part 2.2 — Startup Sequence, Entry Point, IPC Server, and VCS Subsystem

---

##### Kernel Startup Sequence

The startup sequence is a strict ordered pipeline. Each step must succeed before the next begins. There is no partial startup with degraded mode — the kernel either reaches the dispatch loop in a fully consistent state or exits with a typed error code.

| Step | What happens | Failure exit code |
|---|---|---|
| 1 | Parse CLI flags and environment. Detect mode: `normal`, `bootstrap`, or explicit `--recovery-override`. | Non-zero with usage message |
| 2 | If bootstrap mode: enter `bootstrap::run()` state machine. Does not proceed to step 3. Exits 0 on success, `BOOT_ERR_BOOTSTRAP_FAILED` on failure. | `BOOT_ERR_BOOTSTRAP_FAILED` |
| 3 | Load and verify signed policy artifacts from `~/.raxis/policy/` using `raxis-policy::loader`. Verify signature against authority key. | `BOOT_ERR_POLICY_INVALID` |
| 4 | Initialize key registry from loaded policy (`raxis-crypto::keyring`). Verify authority key, quality key, and verifier token key entries are all present and non-expired. | `BOOT_ERR_KEY_REGISTRY` |
| 5 | Open kernel state store (`raxis-store::db`). Verify schema version matches binary. Apply any pending migrations. | `BOOT_ERR_STORE_SCHEMA` |
| 6 | Run `recovery::reconcile(store, audit, witness_idx)` — single `main.rs` call that executes four ordered phases internally: **(6-chain)** verify audit chain (`verify_audit_chain`) — broken/missing chain is **fatal**; **(6-task)** reconcile in-flight tasks (`reconcile_tasks` — sweeps **all non-terminal** tasks: `Admitted` / `GatesPending` / `Running` / `BlockedRecoveryPending` → `BlockedRecoveryPending`, AND captures per-task `prior_state` inside the same transaction so a downstream supervisor-aware fork can decide which rows to auto-resume) — recovery-pending found is **warn + continue**; **(6-orphan-token)** invalidate orphan verifier tokens for swept tasks (`expire_orphan_verifier_tokens`, called from inside `reconcile_tasks`'s recovery transaction — see §4.6) so zombie tokens cannot be honoured if a stray subprocess survives; **(6-witness)** check witness index for orphaned blobs (`witness_index::startup_check`) — discrepancies logged, non-fatal. **V2.5 supervisor-aware fork (`INV-SUPERVISOR-AUTO-RESUME-ON-CLEAN-RESTART-01`):** the swept-tasks-detail vector returned by `(6-task)` is consumed by `recovery::reconcile_after_supervisor_restart` at boot Step 8a''' (after the supervisor's `KernelRestart{Initiated,Completed}` rehydration, before IPC accept); when the previous exit was a supervisor-classified auto-restartable code, every freshly-swept row is unconditionally re-admitted (`BlockedRecoveryPending → Admitted`) EXCEPT operator-quarantined initiatives and rows whose `prior_state` was ALREADY `BlockedRecoveryPending`. The unmonitored / operator-initiated boot leaves swept rows at `BlockedRecoveryPending` per `INV-INIT-05` (operators who want this fail-safe across supervisor restarts disable the supervisor entirely with `RAXIS_SUPERVISOR_AUTO_RESTART=0`). `main.rs` calls `reconcile` once and checks the returned `ReconciliationResult` for fatal vs non-fatal outcomes. **In V2.1+** the entry point is `recovery::reconcile_advisory`, the chain-verification phase calls the `crates/audit/src/verifier.rs` offline verifier (paired-class checks; orphan resolution against the SQLite snapshot per `v2/audit-paired-writes.md §5`), and the chain-repair phase synthesises missing `confirmed` / `StateChangeRolledBack { reason: CrashInferred }` events instead of V1 `ReconciliationGap` records. **Critical findings (chain break, dangling confirmed/rollback, digest mismatch) remain fatal** and require operator override (`raxis audit verify --acknowledge-critical`); chain-orphan resolution against SQLite is a non-fatal advisory pass per `INV-AUDIT-PAIRED-06`. | `BOOT_ERR_AUDIT_CHAIN` (chain broken or critical finding); warn + continue (tasks/witness orphans, advisory orphan resolution) |
| 7 | Bind IPC listener sockets under `<data_dir>/sockets/`. Set directory permissions `0700`. The three socket file names, per-socket file modes, per-socket auth model, and listener binding order are specified in [`kernel-store.md`](kernel-store.md) §2.5.5 three-socket model — `planner.sock` (planner session token + verifier `verifier_run_token` for the `WitnessSubmission` variant), `gateway.sock` (gateway process token), `operator.sock` (challenge-response then operator session token, file mode 0600). There is no separate `witness.sock` file in v1 — verifier subprocesses connect to `planner.sock` (the path advertised in `RAXIS_KERNEL_SOCKET`) and the dispatcher routes by message variant. For v1, all three listeners are bound in this step before the IPC server loop begins. | `BOOT_ERR_SOCKET_BIND` |
| 7a | Open the active audit segment (`<audit_dir>/segment-000.jsonl`) for append. **Chain-resume contract:** before opening, call `raxis_audit_tools::last_chain_state(path)` to scan the existing segment and recover `(next_seq, prev_sha256)`. Three outcomes: **(a) Ok(None)** — file missing or empty (genesis case): pass `starting_seq = 0`, `starting_prev_sha256 = None` to `AuditWriter::open` (uses the all-zero genesis sentinel); **(b) Ok(Some(info))** — chain intact: pass `info.next_seq` and `Some(info.prev_sha256)` so the next event continues the chain across the restart boundary; **(c) Err(...)** — sequence gap, prev_sha256 break, or malformed JSON: fail-closed with `BOOT_ERR_AUDIT_CHAIN`. **Why:** without this scan, every kernel restart would emit `KernelStarted` with `seq = 0`, which `recovery::verify_audit_chain` (step 6-chain) would then fail-close on at the *next* boot — i.e. the kernel would only survive its first start. The scan is O(file_size) but runs once per boot; v1 has no segment rotation so it always scans the active segment. Regression-pinned by `crates/audit/src/writer.rs::tests::resume_and_append_preserves_chain_integrity_end_to_end` plus six additional fail-closed tests. | `BOOT_ERR_AUDIT_CHAIN` |
| 8 | Emit `KernelStarted` audit event (records binary version, policy epoch, recovery_pending task count). On failure: **dual-write to the emergency sink** (`~/.raxis/emergency.log`) then exit `BOOT_ERR_AUDIT_WRITE`. Rationale: if the chain cannot accept a start record, the kernel's audit integrity is already suspect and operating would worsen the problem. The emergency sink preserves the start event for operator inspection. | `BOOT_ERR_AUDIT_WRITE` |
| 9 | Enter IPC dispatch loop (`ipc::server::start`). Process incoming connections until SIGTERM/SIGINT OR an accept loop dies. **Signal handler registration:** the dispatch loop installs `tokio::signal::unix::signal` for both `SIGTERM` and `SIGINT`; the dispatch loop returns a `ShutdownReason` discriminating between operator-initiated (`SigTerm` / `SigInt`) and degraded (`AcceptLoopExited { which }`) exits. **Cleanup contract:** before returning, the dispatch loop unbinds the three UDS sockets by removing their files (best-effort `std::fs::remove_file`); without this, stale socket files would survive across restarts and the next `UnixListener::bind` would fail with `BOOT_ERR_SOCKET_BIND`. If installing the signal handlers themselves fails (rare; out-of-fd or kernel without signalfd), the dispatch loop logs and degrades to "wait for accept-loop exit only" — Ctrl-C still tears the process down via the OS default disposition, just without the `KernelStopped` audit hook. | — |
| 10 | Emit `KernelStopped { reason }` audit event AFTER the dispatch loop returns. The `reason` string is the canonical audit token from `ShutdownReason::audit_reason()`: `"SIGTERM"`, `"SIGINT"`, or `"accept_loop_exited:<which>"` (operator/planner/gateway). This event MUST be the last record in the segment for this kernel-process lifetime so the next boot's `last_chain_state` extends the chain cleanly and so operators inspecting the segment can tell the previous exit was clean. **Exit code:** `ShutdownReason::is_clean()` returns true for `SigTerm` / `SigInt` (process exits 0); false for `AcceptLoopExited` (non-zero so init systems restart the kernel). Pinned end-to-end by `kernel/tests/kernel_signal_shutdown.rs::sigterm_triggers_graceful_shutdown_and_kernel_stopped_audit` plus `audit_chain_intact_across_kernel_started_and_kernel_stopped` and `kernel_can_restart_cleanly_and_chain_persists`. | — |

**Why fail-closed at every step:** A kernel that starts in a partially consistent state will make decisions against stale or unverified policy, against a corrupted state store, or without a trusted audit record. All of these are worse than not starting. The operator can inspect the exit code, read the structured error message, and take corrective action. Degraded-mode operation is not offered in v1.

---

##### Entry Point Subsystem

---

###### `src/main.rs` — [NEW]

**Purpose:** Orchestrates the startup sequence and owns the process lifecycle. Contains no policy logic, no IPC logic, and no authority logic — only sequencing calls and signal handling.

**Why it exists as its own file:** Keeping `main.rs` thin is critical for testability. Integration tests that want to start a kernel subprocess can inspect exactly what `main` does without wading through subsystem logic. Any logic that belongs in a subsystem must live there, not in `main`.

**What it contains:**
- `fn main()` — calls each startup step in order, converts `Err` results to `errors::exit_with_code(err)`. No inline logic.
- Signal handler registration: `SIGTERM` and `SIGINT` both trigger graceful shutdown — drain the IPC handler queue, flush pending audit writes, close the UDS socket, emit `KernelStopped` audit event. **`KernelStopped` failure policy:** dual-write to emergency sink (`~/.raxis/emergency.log`) then exit 0 (best-effort, not `BOOT_ERR_AUDIT_WRITE`). Rationale: a clean shutdown that cannot write its final record is less dangerous than one that refuses to exit, leaving the socket open and the process running. The emergency sink preserves the stop event for operator inspection. This is explicitly different from the `KernelStarted` policy (which is fail-closed) because the risk profile differs: failing to record a start means the kernel might operate without a chain anchor; failing to record a stop means only an audit gap on clean shutdown.
- No `#[tokio::main]` with `flavor = "multi_thread"` and unbounded workers — explicitly configure thread pool size to bound concurrency (v1: `worker_threads = 4` or configurable via env).

---

###### `src/bootstrap.rs` — [NEW]

**Purpose:** Genesis state machine. Entered only when the kernel is started in bootstrap mode (first-time setup or deliberate re-genesis). Mutually exclusive with normal startup — it creates the authority key material and first policy epoch, then exits. It does not enter the IPC dispatch loop.

**Why it is separate from `main.rs`:** The bootstrap path touches key generation, which must never run on a normally-started kernel. Keeping it isolated means the normal startup path cannot accidentally trigger key regeneration, and the bootstrap path cannot accidentally enter production operation.

**What it contains:**
- `pub fn run(config: &BootstrapConfig) -> Result<(), KernelError>` — the genesis state machine entry point. **Thin wrapper:** delegates to `run_inner(config)?` and then calls `std::process::exit(0)` on success. The wrapper exists so production callers cannot accidentally fall through into the IPC dispatch loop after a successful genesis (kernel-core.md §2.2 step 2 mandates that bootstrap mode is mutually exclusive with normal startup), while integration tests can call `run_inner` directly to assert against the resulting on-disk state in-process.
- `pub(crate) fn run_inner(config: &BootstrapConfig) -> Result<(), KernelError>` — the testable inner implementation. Identical to `run` in every observable side effect except that it returns `Ok(())` instead of exiting on success. **Production callers MUST go through `run`**, not `run_inner` — the single-file integration tests at the bottom of `bootstrap.rs` are the only legitimate users.
- `fn generate_authority_keypair() -> KeyPair` — generates the authority signing keypair. Writes to `~/.raxis/policy/authority.key` with `0400` permissions. Fails if the file already exists (never overwrites silently).
- `fn write_genesis_policy(keypair: &KeyPair, epoch: PolicyEpoch) -> Result<()>` — thin I/O wrapper that delegates ALL formatting decisions to `raxis_genesis_tools::render_genesis_policy_toml` (the single canonical emitter shared with the operator-facing `raxis genesis` CLI command). This function is responsible for (a) gathering the operator pubkey + fingerprints, (b) constructing the `<data_dir>/worktrees` placeholder for `sessions.allowed_worktree_roots`, (c) calling the shared emitter, and (d) writing the resulting bytes to disk with mode `0644`. The shared emitter enforces the spec invariants — non-empty allowlist (else `raxis_policy::PolicyBundle::validate` rejects the artifact), the 13 canonical `permitted_ops`, the four canonical `IntentKind` budget keys (`SingleCommit`, `IntegrationMerge`, `CompleteTask`, `ReportFailure`), and the `[[lanes]] default` entry that admission requires.
- `fn write_genesis_audit_record(keypair: &KeyPair) -> Result<()>` — thin I/O wrapper that delegates JSONL rendering to `raxis_genesis_tools::render_genesis_audit_record`. This function is responsible for (a) minting 64 CSPRNG bytes via `raxis_crypto::token::try_random_array::<64>` (= 512 bits, with 256-bit headroom over the spec floor in §2.5.5 `audit-genesis-nonce`), (b) computing the authority fingerprint via the shared `raxis_genesis_tools::pubkey_fingerprint`, (c) calling the shared emitter, and (d) appending the line to `audit/segment-000.jsonl` and `fsync`ing before returning. Write order: (1) write record bytes, (2) `fsync` segment file — matching the chain-write protocol in `raxis-audit-tools` so recovery can detect partial writes. The genesis record is the only `AuditEventKind` with `prev_sha256` set to the all-zeros sentinel (`raxis_genesis_tools::GENESIS_PREV_SHA256`); every subsequent record chains from its hash.
- `fn purge_existing_genesis_artifacts(keys_dir, audit_dir) -> Result<()>` — invoked when `config.force == true`. Deterministically removes every artifact `run_inner` will subsequently try to create with `OpenOptions::create_new` — without this step, the per-file exists-check inside `write_file_0400` would fire mid-ceremony on the second run and the `--force` escape hatch would silently fail (regression-pinned by `bootstrap::edge_cases::second_run_with_force_succeeds_and_overwrites`). Adding any new genesis artifact written via `create_new` to `run_inner` MUST also list it here, or `--force` will break for it. The per-file `create_new` checks are intentionally preserved as a defense-in-depth layer against future code paths that forget to route through this purge.
- Exits the process after completion (via `pub fn run`); does not return to `main`.

**Convergence with the CLI:** the operator-facing `raxis genesis` CLI command (`cli/src/commands/genesis.rs::run_genesis`) and this kernel-side `bootstrap::run_inner` both call the SAME `raxis_genesis_tools::render_genesis_policy_toml` and `render_genesis_audit_record` functions. There is no separate kernel emitter and no separate CLI emitter — the two paths share one canonical implementation. See `crates/genesis-tools/src/lib.rs` for the drift-history rationale (five distinct drifts before convergence, two of which were latent P0s); see [`philosophy.md`](philosophy.md) §1.6 `crates/genesis-tools/` for the dependency-graph contract. Both `bootstrap::integration::*` tests in this file AND `cli/tests/genesis_emitter_round_trip.rs` pin the round-trip through `raxis_policy::load_policy`, so a regression in either the emitter or the loader surfaces immediately.

---

###### `src/recovery.rs` — [NEW]

**Purpose:** Post-crash reconciliation. Runs at the end of startup (step 6). Verifies the audit chain is intact, identifies tasks that were in-flight at crash time, and marks them `blocked_recovery_pending` so the operator can inspect and manually resume or discard. The generic crash-recovery fork does not resume any execution automatically — that surface is `INV-INIT-05`.

**V2.5 supervisor-aware fork.** When the supervisor restarts the kernel after an auto-restartable exit code, the boot sequence layers `recovery::reconcile_after_supervisor_restart` over the generic sweep at boot Step 8a''' (after the supervisor's restart-lifecycle audit events, before IPC accept). That fork transparently re-admits every freshly-swept task (`BlockedRecoveryPending → Admitted` via the same `task_transitions::transition_task` API the operator `task resume` IPC handler uses, with `actor = "kernel"` so audit-chain readers can mechanically distinguish operator-initiated resumes from supervisor-initiated resumes), with two skip clauses: (a) operator-quarantined initiatives, and (b) tasks whose `prior_state` captured by the SELECT-then-UPDATE in `(6-task)` was ALREADY `BlockedRecoveryPending` (preserve pre-existing operator block). The contract is unconditional when the supervisor is enabled — see `v2/self-healing-supervisor.md §3.5` and `INV-SUPERVISOR-AUTO-RESUME-ON-CLEAN-RESTART-01`. Operators who want the V1 fail-safe to apply across supervisor restarts disable the supervisor entirely (`RAXIS_SUPERVISOR_AUTO_RESTART=0`).

**Why automatic resumption is not done here:** Resuming an in-flight task after a crash requires knowing whether the last action before the crash completed or not. Without a two-phase commit between the state store and the audit log, automatic resumption could double-execute a task step. In v1 the operator makes that determination. Automatic resumption is a v2 feature gated behind `cfg(feature = "v2-auto-recovery")`.

**What it contains:**
- `pub fn reconcile(store: &Store, audit: &AuditTools, witness_idx: &WitnessIndex) -> ReconciliationResult` — the single entry point called from `main.rs` step 6. Orchestrates all sub-steps internally in this order (the labeled phases in the startup table): (1) `verify_audit_chain` (fatal on failure, maps to `BOOT_ERR_AUDIT_CHAIN`), (2) `reconcile_tasks` (warn on recovery-pending; transitively invokes `expire_orphan_verifier_tokens` for the swept tasks — see §4.6 `recovery.rs` for both functions), (3) `witness_index::startup_check` (log orphan discrepancies). `main.rs` calls `reconcile` once; it does not call the sub-functions directly.
- `fn verify_audit_chain(audit: &AuditTools) -> Result<ChainCheckpoint, KernelError>` — calls `audit_tools::verifier::verify_chain(None)` for full chain verification; returns the last verified segment + hash as a `ChainCheckpoint` for anchoring future writes. **Fatal failure path**: returns `Err(KernelError::AuditChainBroken)` which `reconcile` propagates; `main.rs` maps to `BOOT_ERR_AUDIT_CHAIN`. **Fail-closed contract** (v1 review item #15, regression-tested in `kernel/src/recovery.rs`): every degraded outcome MUST raise `AuditChainBroken` — there is no fail-open path. The check rejects: (a) missing `<audit_dir>/segment-000.jsonl`, (b) zero-byte segment file, (c) segment whose first line is blank, (d) first line that is not valid JSON, (e) genesis record missing the required `seq` field (or wrong type), (f) genesis record missing the required `event_kind` field (or wrong type), (g) `seq != 0` or `event_kind != "GenesisRecord"`. v1's structural check is intentionally narrower than v2's full hash-chain verification, but it MUST never be looser than this list — silently defaulting any field is a spec violation. The only legitimate way to start a kernel without a chain is to run `raxis genesis` (which writes the segment) before launching the kernel.
- `fn reconcile_tasks(store: &Store) -> ReconciliationReport` — selects all tasks whose state is **not** terminal: **`NOT IN (Completed, Failed, Aborted, Cancelled)`**. **`Cancelled` is terminal** — including it in this predicate is mandatory so bulk-cancelled tasks are never swept into `BlockedRecoveryPending`. For every row returned, transitions the task to **`BlockedRecoveryPending`** with `recovery_transition_at` (including tasks already in `BlockedRecoveryPending` — update is idempotent). v1 does not exempt `Admitted` vs `GatesPending` vs `Running`; all non-terminal tasks need operator disposition after an unclean shutdown.
- `fn mark_recovery_pending(store: &Store, task_ids: Vec<TaskId>) -> Result<()>` — performs the state transition batch for the matched task IDs (implementation detail of `reconcile_tasks`).

---

###### `src/errors.rs` — [NEW]

**Purpose:** Shared vocabulary for all kernel failure modes. Every subsystem that can fail at startup or runtime uses types from this file. Prevents each subsystem from inventing its own error strings or exit codes.

**Why it is a single file at the root:** Boot errors need to be visible across `main.rs`, `bootstrap.rs`, `recovery.rs`, and all subsystem init functions. Placing it at the crate root makes it accessible everywhere without re-export chains.

**What it contains:**
- `BOOT_ERR_POLICY_INVALID: i32 = 10`, `BOOT_ERR_KEY_REGISTRY: i32 = 11`, `BOOT_ERR_STORE_SCHEMA: i32 = 12`, `BOOT_ERR_AUDIT_CHAIN: i32 = 13`, `BOOT_ERR_SOCKET_BIND: i32 = 14`, `BOOT_ERR_BOOTSTRAP_FAILED: i32 = 15`, `BOOT_ERR_AUDIT_WRITE: i32 = 16`, `BOOT_ERR_VCS_ROOT: i32 = 17` — typed exit codes, documented in operator runbook. New codes added for step 8 (audit write failure) and vcs root validation failure at startup.
- `enum KernelError` — runtime error enum with variants for each subsystem failure class. Implements `Display` with structured messages.
- `fn exit_with_code(err: KernelError) -> !` — logs `err` as a structured JSON line to stderr, then calls `std::process::exit(err.exit_code())`. The `-> !` ensures the compiler knows this never returns.

---

##### IPC Server Subsystem

The IPC server is the kernel's public surface — the only interface through which the planner, gateway, verifier, and CLI reach the kernel. Every inbound message passes through three layers in sequence: **listener** (accept connection) → **auth** (validate token, sequence, nonce) → **dispatcher** (route to handler). A message rejected at any layer never reaches the next.

---

###### `src/ipc/mod.rs` — [NEW]

**Purpose:** Wires listener, auth, and dispatcher together and exposes `start_ipc_server` as the single entry point called from `main.rs`. Contains no logic of its own.

**What it contains:**
- `pub async fn start_ipc_server(socket_path: &Path, handlers: Handlers) -> Result<(), KernelError>` — creates the UDS listener, passes it to `listener::accept_loop`.

---

###### `src/ipc/listener.rs` — [NEW]

**Purpose:** Accepts UDS connections and spawns a per-connection async task. Each task is independent — one slow or misbehaving connection cannot block others.

**Why per-connection tasks, not a single shared loop:** A shared loop would serialize all message processing, making the kernel unresponsive if one handler blocks (e.g., waiting on a verifier subprocess). Per-connection `tokio::spawn` gives concurrent handling. **Connection concurrency is bounded**: the accept loop enforces a configurable `max_connections` limit (v1 default: 16 — the expected clients are planner, gateway, verifier, and CLI, so 16 is generous). When the limit is reached, new connections are accepted and immediately closed with an error frame; the attempt is logged. This prevents a DoS from unbounded task accumulation.

**What it contains:**
- `pub async fn accept_loop(listener: UnixListener, auth: Arc<AuthValidator>, dispatcher: Arc<Dispatcher>) -> Result<(), KernelError>` — loops on `listener.accept()`; for each connection calls `tokio::spawn(handle_connection(stream, auth.clone(), dispatcher.clone()))`.
- `async fn handle_connection(stream: UnixStream, auth: Arc<AuthValidator>, dispatcher: Arc<Dispatcher>)` — reads length-prefixed frames using `raxis-ipc::frame`, deserializes `IpcMessage`, passes to `auth.validate`, passes to `dispatcher.dispatch` on success.
- Connection-level timeout: if no message is received within a configurable idle window (v1 default: 30s), the connection is closed and an `IdleConnectionClosed` audit event is emitted.

---

###### `src/ipc/auth.rs` — [NEW] — Enforcement point for INV-01

**Purpose:** The single choke point for all inbound message authentication. Every message from every process passes through `validate` before reaching any handler. A message that fails validation never reaches the dispatcher.

**Why authentication is not in the dispatcher:** The dispatcher's job is routing. If auth were inlined in the dispatcher, it would be possible to add a new message variant and accidentally forget to add its auth check. Separating auth into a dedicated module ensures there is exactly one place where the auth invariant is enforced, regardless of how many message variants exist.

**What it contains:**
- `pub struct AuthValidator { session_store: Arc<Store>, verifier_token_store: Arc<VerifierTokenStore>, nonce_cache: Arc<NonceCache> }` — two separate stores: `session_store` holds planner and gateway session rows; `verifier_token_store` holds kernel-issued verifier run tokens (separate table, separate lookup path in `authority::verifier_token`). Verifier run tokens are not session rows and must not be validated against the session table. (Implementation detail deferred to Part 2.3.)
- `pub fn validate(envelope: &IpcEnvelope) -> Result<ValidatedSession, AuthError>` — branches on message class before applying auth rules:
  - **Planner / gateway session messages**: (1) token lookup in `session_store` via `session_id`; (2) constant-time token binding check against `sessions.session_token`; (3) **check (A) — strict sequence**: verify `sequence_num == sessions.sequence_number + 1` (read from the session row loaded in step 1); (4) **check (B) — envelope nonce**: `INSERT INTO nonce_cache (session_id, sequence_num, envelope_nonce, observed_at) VALUES (?, ?, ?, now())` — fails with `SQLITE_CONSTRAINT_UNIQUE` on duplicate `envelope_nonce` (duplicate delivery) or `SQLITE_CONSTRAINT_PRIMARYKEY` on duplicate `sequence_num` (schema backstop for check A); (5) `UPDATE sessions SET sequence_number = sequence_num` atomically with step 4 in one store transaction. All five checks must pass. See §2.5.1 Table 16 for the canonical INV-01 enforcement sequence.
  - **Verifier run token messages** (e.g. `WitnessSubmission`): (1) token lookup in `verifier_token_store` by `verifier_run_id`; (2) constant-time comparison of the presented 256-bit random token bytes against the stored `token_hash` (SHA-256 of raw bytes). **Sequence and nonce rules do not apply** — verifier runs are one-shot submissions. INV-01 for verifier messages means: the token is valid (lookup succeeds, hash matches), non-expired, and not yet consumed.
  - Any message that does not match a known class → `Err(AuthError::UnknownMessageClass)`, connection closed.
- `struct NonceCache` — thin wrapper around the `nonce_cache` SQLite table (§2.5.1 Table 16). **Not an in-memory HashMap.** All reads and writes go through the store transaction in `validate()`; no in-process cache is maintained. The SQLite-backed design was chosen because the nonce check must survive a process restart (an in-memory cache would lose all nonces on crash, reopening a replay window until the TTL window expires). Background eviction of rows older than `NONCE_CACHE_TTL_SECONDS` runs in the dispatcher's background task, not inside `NonceCache` itself.
- **Invariant INV-01**: this function is the structural enforcement point. If this function is bypassed, the entire authority model fails.

---

###### `src/ipc/dispatcher.rs` — [NEW] — Enforcement point for INV-08

**Purpose:** Routes validated `IpcMessage` variants to the correct handler. Also the sole layer that maps internal typed errors to coarse planner-facing response codes — enforcing INV-08.

**Why a dedicated dispatcher rather than a match in each handler:** If each handler wrote its own response serialization, the coarse-code rule (INV-08) would need to be enforced in every handler. A single dispatcher is the only place where that mapping happens; adding a new handler does not create a new INV-08 surface.

**What it contains:**
- `pub struct Dispatcher { handlers: Handlers }` where `Handlers` is a struct holding `Arc<IntentHandler>`, `Arc<FetchHandler>`, `Arc<WitnessHandler>`, `Arc<ProposalAppendHandler>`, `Arc<EscalationHandler>`.
- `pub async fn dispatch(msg: IpcMessage, session: ValidatedSession) -> IpcResponse` — pattern-matches on `IpcMessage` variant; routes to the corresponding handler; catches `HandlerError` variants and maps them to `IpcResponse::Error(PlannerErrorCode)`. The catch-all arm maps any unrecognized variant to `IpcResponse::Error(PlannerErrorCode::InvalidRequest)`. Verifier sessions attempting to send `EscalationRequest` are rejected at this layer before reaching `EscalationHandler` (role check).
- `fn map_error(err: HandlerError) -> PlannerErrorCode` — the INV-08 enforcement function. Maps `HandlerError::MissingWitness` → `FAIL_MISSING_WITNESS`, `HandlerError::PolicyViolation` → `FAIL_POLICY_VIOLATION`, `HandlerError::TaskNotSchedulable { .. }` → `FAIL_TASK_NOT_RUNNING`, etc. Internal error details (which rule, which policy line) are logged to the audit log but never included in the `PlannerErrorCode` sent to the planner. **`MissingWitness` aggregates** claim-manifest deficiencies at intent time and witness deficiencies where the handler collapses them to this variant — see §1.3 INV-08 coarse-code note.

---

###### `src/ipc/handlers/intent.rs` — [NEW]

> **V2.1 paired-audit ordering.** Under V2.1+ every state-mutating
> branch of this handler routes through the three-phase paired-write
> protocol defined in `v2/audit-paired-writes.md §2.3`:
>
> 1. **Phase B0 (pre-tx audit) — emit `StateChangePending` and fsync.**
>    After Phase A gates pass and before `BEGIN IMMEDIATE`, the handler
>    computes `pre_state_digest` over the read-set rows (the `tasks` row
>    being bound, the affected `initiatives` row, the candidate
>    `lane_budget_reservations` row, the relevant `delegations` rows for
>    the claim set), `intended_writes` over the rows it intends to
>    mutate (task transition, lane reservation insert, optional
>    `tasks.session_id` UPDATE), and `intended_post_state_digest`. The
>    pending event carries the planner's `idempotency_key` (the
>    `IntentRequest` envelope nonce) so the operator UI can collapse
>    retried-but-then-committed intents.
> 2. **Phase B1 (state mutation) —** `BEGIN IMMEDIATE`, all writes
>    (every mutation also sets
>    `last_committing_event_seq = pending_seq` per §3.1 of
>    audit-paired-writes), compute `actual_post_state_digest` over the
>    write-set rows pre-`COMMIT`, then `COMMIT` and read
>    `PRAGMA data_version` for `sqlite_commit_id`.
> 3. **Phase B2 (post-commit audit) —** emit the existing-kind event
>    (`TaskTransitioned`, `IntentReceived`, etc.) augmented with
>    `confirms_pending_seq`, `sqlite_commit_id`, and
>    `actual_post_state_digest`; fsync; only then return
>    `IntentResponse::Accepted` to the planner.
>
> Deliberate rollbacks (constraint violation, lock timeout) emit
> `StateChangeRolledBack { rolls_back_pending_seq, reason: ... }` in
> Phase B2 instead, fsync, then return `IntentResponse::Rejected`.
> Phase-A rejections (budget exhausted, gate denial, unauthorised
> session) remain single-event under V1 semantics — they never reach
> Phase B0 because no SQLite mutation occurs.
>
> The handler MUST NOT short-circuit pending fsync on the assumption
> that Phase B1 will succeed. The pending event records "the kernel
> attempted this transition under these preconditions" and is
> chain-bound regardless of Phase B1 outcome. See `v2/audit-paired-
> writes.md §7` for the per-crash-window resolution table and §9 for
> the threat model that motivates the pre/post digest binding.

**Purpose:** Handles `IntentRequest` from the planner. The intent handler is the entry point for all planner-initiated work: it validates the session's claim set and SHA range, binds the existing plan task to the current session, evaluates gate claims, reserves lane budget, and transitions the task to `Running` or `GatesPending`.

**What it contains:**
- `pub async fn handle(req: IntentRequest, session: ValidatedSession, ctx: &HandlerContext) -> Result<IntentResponse, HandlerError>`
- **Two-SHA validation** — `IntentRequest` carries `head_commit_sha` and `base_commit_sha`. Both must be 40-char hex SHAs. Branch refs (`main`, `HEAD`, `origin/main`) and short SHAs are rejected; accepting a ref would make the diff non-deterministic across re-evaluation.
- **Ancestor check** — calls `ctx.vcs.is_ancestor(base_sha, head_sha, worktree_root)` before any diff. If base is not an ancestor of head, the kernel rejects with `HandlerError::InvalidShaRange`. The planner cannot shrink the diff by providing a false base. When **`base_sha == head_sha`**, this is the reflexive case (empty commit range per §2.5.8); `is_ancestor` must succeed so the handler can compute an empty `touched_paths` without special-casing ancestor logic beyond that.
- **Single-commit parent verification (v1 hardening)** — applies only when `req.intent_kind == IntentKind::SingleCommit` **and** `base_sha != head_sha`. The kernel runs `ctx.vcs.rev_parse_parent(head_sha, worktree_root)` and requires the result to equal `base_sha`; otherwise rejects with `HandlerError::InvalidShaRange`. When **`base_sha == head_sha`**, this check is **skipped**: there is no single-commit “tip whose parent must equal base” — the range is intentionally empty (same rule as Part 3 field notes and §2.5.8 empty-diff rows). For non-empty `SingleCommit` ranges, the parent rule still prevents a planner-chosen `base_sha` from under-covering `touched_paths`.
- **Range diff** — calls `ctx.vcs.touched_paths(base_sha, head_sha, worktree_root)` to get all paths changed across the full range. `worktree_root` is bound to this session at session creation time (the agent's git worktree, not process cwd). The `worktree_root`, `base_sha`, and `head_sha` used are all included in the `IntentReceived` audit event (INV-05).
- Discards any planner-supplied path manifest in the request — VCS-derived range paths only.
- **Admission cost computation** — calls `budget::compute_admission_cost(&touched_paths, req.intent_kind, &policy)`. `touched_paths` is the VCS-derived sorted list from the previous step — the same list used for INV-07 claim evaluation; no re-derivation. On `Err(BudgetError::UnknownIntentKindCost { intent_kind })` → returns `Ok(IntentResponse::Rejected { reason: PlannerErrorCode::FAIL_POLICY_VIOLATION })` immediately; no task row binding, no scheduler interaction, no witness or audit rows written beyond `IntentRejected`. On `Ok(cost)` → `estimated_cost = cost` is held in local scope for the budget reservation step that runs after gate evaluation. `IntentRequest` carries no cost field; even if a future version adds a hint field, it must not be passed to `compute_admission_cost` or `consume_budget` — see `IntentRequest` guardrail in `raxis-types`.

  > **Guardrail — coordinated release:** when a new `IntentKind` variant is introduced in `raxis-types`, a corresponding entry in `policy.budget.base_cost_per_intent_kind` must be present in the loaded policy artifact before or simultaneously with the binary that adds the variant. A kernel binary whose cost table omits a live `IntentKind` will reject all intents of that kind with `FAIL_POLICY_VIOLATION`. This is intentional — it enforces explicit operator acknowledgement of new surface area. Operational story: ship the updated policy artifact first (or atomically with the binary); never ship a binary with a new `IntentKind` against a policy that does not price it.
- **Task row binding** — tasks already exist in the `tasks` table from `approve_plan` with plan-defined `task_id` values (Part 2.4 INV-INIT-01). The intent handler does **not** insert a new task row and does **not** call `Uuid::new_v4()`. Instead:
  1. **Load existing task row** by `req.task_id`. If no row → `HandlerError::InvalidTask`. If `task.initiative_id` does not belong to an initiative in `Executing` state → `HandlerError::InitiativeNotExecuting`.
  2. **Session exclusivity** — if `task.session_id IS NOT NULL` and `task.session_id != session.session_id`, return `HandlerError::Unauthorized` (another session owns this task). If `task.session_id IS NOT NULL` and matches `session.session_id`, the same planner continues work on an already-bound task (**pickup** or **continuation**).
  3. **Schedulability** — If `task.state == TaskState::Running` and `task.session_id == session.session_id`, proceed (**continuation intent** — matches `IntentRequest` semantics in `raxis-types`; `next_ready_tasks` is not consulted). If `task.state == TaskState::Admitted`, require `req.task_id ∈ scheduler::next_ready_tasks(initiative_id, store)`; membership is the single gate for pickup and for returning from `GatesPending → Admitted` (both are `Admitted` rows eligible per DAG + gate rules — see `scheduler::next_ready_tasks`). If the task is `Admitted` but **not** in that set (e.g. predecessors incomplete), → `HandlerError::TaskNotSchedulable`. Any other state (`GatesPending`, `BlockedRecoveryPending`, terminal, wrong session after step 2) → `HandlerError::TaskNotSchedulable { current_state }`.
  4. **Bind or refresh SHA fields** — `UPDATE` the task row with `session_id` (= current session, if still NULL), `evaluation_sha` (= `req.head_commit_sha`), `base_sha` (= `req.base_commit_sha`), and `submitted_claims_json` (= `req.claims.as_json()`; **note: persisted for audit/forensic purposes only — the kernel discards planner-submitted claims at gate evaluation time and auto-derives claims from witness records; see `gates/mod.rs` Step 2.5**). On first pickup `session_id` is written; on continuation it is unchanged. This `UPDATE` is part of the enclosing handler transaction; if any subsequent step fails, it rolls back (for first pickup, restoring NULL session fields where applicable).
- **Gate evaluation** — calls `ctx.gates.evaluate_claims(session_id, &req.head_commit_sha, &req.task_id, &touched_paths, &req.claims, ctx)`. **Note: `req.claims` is passed for wire compatibility but is discarded by `evaluate_claims` Step 2.5 — the kernel auto-derives all claims from its own witness records.** Gate evaluation runs before budget reservation — on any `GateEvalResult::ClaimInsufficient` variant (`Insufficient`, `DelegationInsufficient`, or `ScopeInsufficient`), the handler returns rejection immediately and the enclosing transaction rolls back the binding `UPDATE`. No budget is touched on a gate rejection.
- **Budget check and reservation** — runs only after gate evaluation returns `Pass`, `BreakglassPass`, or `PendingWitness`. **`lane_budget_reservations` uses `PRIMARY KEY (lane_id, task_id)`** — at most one reservation row per task per lane for the task's whole non-terminal life (including `Admitted → GatesPending → Admitted` witness cycles). Therefore:
  - If **no** row exists yet for `(task.lane_id, req.task_id)`: call `ctx.budget.check_budget(task.lane_id, estimated_cost, store)` then `ctx.budget.consume_budget(task.lane_id, req.task_id, estimated_cost, store)`, and **`UPDATE tasks SET admission_reserved_units = estimated_cost`** for this `task_id` (persists the lane reservation amount for `BudgetOverrun` after `release_budget` deletes the reservation row — typically first intent from `Admitted` to `Running` or `GatesPending`).
  - If a row **already** exists: **omit** `check_budget` and `consume_budget` — same task, additional intent turn (e.g. `Running` continuation, or re-scheduled `Admitted` after `GatesPending` without a terminal release). A second `INSERT` would violate the PK or double-charge the lane.
  `actual_cost` on the task row is still updated by `budget::reconcile_actual_cost` on terminal transition.
- **Transition task** — after budget handling, apply state transitions only when the stored state actually changes (signature matches `task_transitions.rs`):
  - `GateEvalResult::Pass` or `GateEvalResult::BreakglassPass` → if current state is `Admitted`, call `transition_task(req.task_id, TaskState::Running, None, TransitionActor::Kernel, policy_epoch, &ctx.store, &ctx.audit)`. If already `Running` (continuation intent, state unchanged), **skip** `transition_task` — the state does not change and emitting a spurious `TaskTransitioned` event would be incorrect. The `IntentReceived` audit event (emitted at the start of the handler) records the continuation intent.
  - `GateEvalResult::PendingWitness` → current state must be `Admitted` here (step 3 rejects `GatesPending` with `TaskNotSchedulable`). Call `transition_task(req.task_id, TaskState::GatesPending, None, TransitionActor::Kernel, policy_epoch, &ctx.store, &ctx.audit)`. Verifier(s) are spawned inside `evaluate_claims` for each missing gate (see `gates/verifier_runner.rs`).
- Returns the canonical `IntentResponse` enum normatively defined in [`philosophy.md`](philosophy.md) `crates/types/src/intent.rs`. Concretely, the handler builds:
  - On accept: `IntentResponse::Accepted { task_id: req.task_id, task_state, remaining_budget, warn_delegation_stale }`, where `task_state` is read from the task row after the `transition_task` call above (so it reflects the post-transition state — `Running` for `Pass`/`BreakglassPass`, `GatesPending` for `PendingWitness`, or unchanged on continuation), `remaining_budget` is read from `lane_budget_reservations` after `consume_budget` (or the existing reservation row when the handler took the "row already exists" branch in step "Budget check and reservation" above), and `warn_delegation_stale` is set from `GateEvalResult::Pass { delegate_renewal_required }` (or `false` for `BreakglassPass` / non-stale `Pass`).
  - On reject: `IntentResponse::Rejected { reason, error_detail, task_state }`. `reason` comes from `dispatcher::map_error` (or the direct return path for `BudgetError::UnknownIntentKindCost` documented in §3.5), `error_detail` is `None` for every code except `FAIL_POLICY_VIOLATION` (INV-08 enforcement — see [`peripherals.md`](peripherals.md) §3.1 field rules), and `task_state` is read from the task row at the time of rejection (the binding `UPDATE` has rolled back if the rejection happened before commit, so this is the last committed state — e.g. `Admitted` if the rejection fired before pickup, `Running` if the rejection fired on a continuation intent, `BlockedRecoveryPending` if the operator interrupted the task between this and the prior IPC turn).
  - The wire JSON projection of these variants — including which fields appear in the envelope vs the payload — is normatively defined in [`peripherals.md`](peripherals.md) §3.1 (`IntentResponse` wire shape).

> **Part 2.3 amendment — `scheduler/admit.rs`:** The `admit` function is **not called from the intent handler**. `admit` is called exclusively from `initiatives::lifecycle::approve_plan` at plan approval time. The function contract has also changed: it no longer accepts `NewTask` or `initial_state`, does not call `check_budget` or `consume_budget`, and does not `TaskAdmitted`-audit with `estimated_cost`. The new contract is `admit(task: PlanTask, initiative_id, policy_epoch, store, audit)` — task row + DAG edge insertion only. All Part 2.3 text that implies `admit` runs budget steps or is called from `handlers/intent.rs` is superseded by this amendment and by Part 2.4 §4.6.

---

###### `src/ipc/handlers/fetch.rs` — [NEW] — Enforcement point for INV-02B

**Purpose:** Handles `FetchRequest` from the planner. All external data the planner needs must go through this handler. The handler enforces the domain allowlist, forwards to the gateway, logs the fetch before returning content to the planner.

**What it contains:**
- `pub async fn handle(req: FetchRequest, session: ValidatedSession, ctx: &HandlerContext) -> Result<FetchResponse, HandlerError>`
- Calls `ctx.provider.allowlist.check(req.url)` — returns `HandlerError::FetchDenied` if URL is not on the allowlist; emits `AuditEventKind::FetchDenied { deny_reason: DomainNotAllowed }` before returning.
- Calls `ctx.provider.execute_fetch(url, session_id)` to run the full fetch pipeline (rate limit → gateway forward → SHA-256 → audit before return). `ctx.provider` is `Arc<ProviderCtx>`; `ProviderCtx` holds the `GatewayChannel` internally (implemented in `provider/gateway.rs`). The handler does not call the gateway channel directly.
  - `ProviderError::RateLimitExceeded` from `check_rate_limit` inside `execute_fetch` maps to `HandlerError::FetchDenied` — the same handler error as allowlist denial — so both deny paths produce identical planner-visible behavior (`PlannerErrorCode::FETCH_DENIED`). The `deny_reason` distinction lives in the audit record (`FetchDenyReason::RateLimitExceeded`), not in the planner-facing code.
- Computes `response_sha256` over the response body before any other processing.
- Emits `AuditEventKind::FetchExternalDataAudited { fetch_request_id, url, fetched_at, response_sha256, content_type, byte_len, allowed_by_domain_allowlist: true }` — written to audit log **before** the body is returned to the planner (INV-02B, INV-05).
- Returns `FetchResponse { fetch_request_id, response_sha256, content_type, byte_len, body }`.

---

###### `src/ipc/handlers/witness.rs` — [NEW]

**Purpose:** Handles `WitnessSubmission` from the verifier subprocess. Validates the `verifier_run_token`, hashes the body, writes to the witness index, then performs a gate-recheck for the associated task. If all outstanding gates are now satisfied, transitions the task from `GatesPending` to `Admitted`.

**What it contains:**
- `pub async fn handle(sub: WitnessSubmission, session: ValidatedSession, ctx: &HandlerContext) -> Result<WitnessAck, HandlerError>`
- **Async-safety contract:** every `Store` access this handler makes (`validate_verifier_token`, `load_task_row`, `witness_index::write`, `consume_verifier_token`, `scheduler::transition_to_admitted`) is **synchronous** — it acquires `Store::lock_sync()` → `tokio::sync::Mutex::blocking_lock()`, which **panics** if invoked from a tokio worker thread ("Cannot block the current thread from within a runtime"). Each such call MUST be wrapped in `tokio::task::spawn_blocking(move || { ... }).await` from this `async` function. This is the same contract `gates::verifier_runner::spawn_verifier` follows for `issue_verifier_token`. Pre-fix, the witness handler called these helpers directly and would have crashed the planner socket task on the very first verifier submission against a multi-thread runtime — pinned by `gates/verifier_runner.rs::stub_round_trip::*` and surfaced when the `raxis-verifier-stub` round-trip test landed.
- **Token validation**: validates `sub.verifier_run_token` via `authority::verifier_token::validate` (wrapped in `spawn_blocking` per the async-safety contract above). Returns `HandlerError::Unauthorized` if invalid, expired, or already consumed.
- **Evaluation SHA binding (before any write):** loads the task row by `sub.task_id`. If no row → `HandlerError::InvalidTask`. Compares `sub.head_commit_sha` to `task.evaluation_sha` (the head_commit_sha stored on the task row when the intent handler bound the task to the planner session). If they differ, returns **`Ok(WitnessAck::Rejected { reason: EvaluationShaMismatch })`** — **no** witness write, **no** token consume, **no** `WitnessAccepted` audit. This catches verifier/kernel bugs or a mismatched submission without poisoning the witness index.
- **Body hash**: computes `blob_sha256 = sha256(sub.body)` (must match the value embedded in `WitnessRecord`).
- **Witness write**: builds `WitnessRecord { evaluation_sha: sub.head_commit_sha, task_id: sub.task_id, gate_type: sub.gate_type, verifier_run_id, blob_sha256, result_class, blob_path: blob_sha256_hex, recorded_at }` where `blob_sha256_hex` is the lowercase hex string of `blob_sha256`, and `result_class` is **`Pass` / `Fail` / `Inconclusive`** (carried on `WitnessSubmission` once the IPC schema wires it, or derived from the verifier subprocess exit status and normalized in this handler — fields must match §2.5.1 Table 13 `witness_records`). Calls `ctx.witness_index.write(record, sub.body.as_slice(), &ctx.witness_index_ctx)` — **blob bytes and `WitnessIndexCtx` are mandatory** (`HandlerContext` exposes `witness_index_ctx`; see `witness_index.rs`). Routes through `witness_index` facade only.
- **Token consume**: calls `authority::verifier_token::consume_verifier_token(verifier_run_id, &ctx.store)` after the witness write succeeds. Ordering is write-then-consume: if the write fails, the token is not consumed and the verifier may resubmit.
- **Audit**: emits `AuditEventKind::WitnessAccepted { verifier_run_id, task_id, evaluation_sha, gate_type, blob_sha256 }`.
- **Gate-recheck**: after a successful write, loads the task row from store via `task_id` to retrieve `task.session_id` (the planner's session, stored when the intent handler bound the task), `task.evaluation_sha` (= head_commit_sha), and `task.base_sha` (= base_commit_sha). Re-derives `touched_paths` from VCS by calling `ctx.vcs.touched_paths(task.base_sha, task.evaluation_sha, worktree_root)` — the same derivation the intent handler performed, ensuring the recheck uses exactly the same VCS-derived path set as the original evaluation. Also loads `session.worktree_root` via `authority::get_session(&task.session_id)`. Calls `ctx.gates.evaluate_claims(task.session_id, &sub.head_commit_sha, &sub.task_id, &touched_paths, &task.submitted_claims_json.parse(), ctx)`. **`task.session_id` is used, not `sub.session_id`** — the verifier's `ValidatedSession` is verifier-scoped and carries no planner delegations. **Note:** `submitted_claims_json` is passed for API compatibility but is discarded at Step 2.5 — the re-check auto-derives claims from the freshly-written witness records.
  - If result is `GateEvalResult::Pass`: calls `ctx.scheduler.transition_to_admitted(&sub.task_id)` to move the task from `GatesPending` to `Admitted`. Emits `AuditEventKind::TaskGatesCleared { task_id, final_witness_run_id: verifier_run_id }`.
  - If result is `GateEvalResult::PendingWitness { missing_gates }`: the kernel **automatically spawns** a new verifier for each gate in `missing_gates` by calling `ctx.gates.verifier_runner::spawn_verifier(task_id, gate_type, evaluation_sha, session.worktree_root, &ctx.authority, &ctx.config.verifier)` for each. The planner does not poll; the kernel drives the full witness-collection loop. `WitnessAck` carries `remaining_gates` as an informational field for observability, not as an instruction to the planner.
  - If result is any claim/delegation failure variant: the witness is accepted and in the index, but the gate failure is audited and the task remains `GatesPending`. The kernel does **not** auto-spawn further verifiers — a claim failure requires planner action (submit correct claim) before the next evaluation cycle.
- **Successful witness pipeline:** returns `WitnessAck::Accepted { verifier_run_id, remaining_gates: Vec<GateType> }` (empty `remaining_gates` = all gates cleared; non-empty = verifiers already spawned by kernel, informational only).
- **Rejected acknowledgment (SHA binding only):** returns `WitnessAck::Rejected { reason: EvaluationShaMismatch }` when `sub.head_commit_sha != task.evaluation_sha` — distinct from `Err(HandlerError::...)`, which signals transport/auth failures to the dispatcher; **`Rejected` is an Ok variant** so the verifier receives a typed refusal without consuming the run token.


---

###### `src/ipc/handlers/escalation.rs` — [NEW] — Escalation FSM entry point

**Purpose:** Handles `EscalationRequest` from the planner. Records the escalation in the kernel state store, enforces the probe-rate-limiter, emits the audit event, and triggers the operator notification. Does not make any authority decision — it submits the request for human resolution.

**What it contains:**

- `pub async fn handle(req: EscalationRequest, session: ValidatedSession, ctx: &HandlerContext) -> Result<EscalationResponse, HandlerError>`

  **Step 1 — Rate-limit check:**
  - Reads the per-lineage escalation counter from the store for the current window (`ctx.policy.escalation_window()`).
  - **Quarantine check first:** if the lineage's quarantine flag is set → returns `Ok(EscalationResponse::Rejected { reason: EscalationErrorCode::LineageQuarantined })` immediately, without incrementing the counter or running any further checks.
  - If `count >= ctx.policy.escalation_max_per_window()` → increments the cumulative trigger count, emits `AuditEventKind::EscalationRateLimitExceeded { session_id, lineage_id, window_count }`, and returns `Ok(EscalationResponse::Rejected { reason: EscalationErrorCode::RateLimitExceeded })`.
  - If the cumulative trigger count (after increment) now equals `ctx.policy.escalation_quarantine_threshold()` → additionally sets the quarantine flag and emits `AuditEventKind::LineageQuarantined { lineage_id, trigger_count }` in the same response. The Nth submission that tips the threshold receives `Rejected { reason: RateLimitExceeded }` (not yet quarantined at receipt, but quarantine is set before returning); subsequent submissions see the quarantine check fire first. Quarantine is lifted only by operator CLI (`raxis-cli quarantine lift <lineage_id>`).

  **Step 2 — Task ownership check:**
  - Loads the task row for `req.task_id`. If no row → `HandlerError::InvalidTask`.
  - Verifies `task.session_id == session.session_id`. If not → `HandlerError::Unauthorized` (a planner cannot escalate on behalf of another session's task).

  **Step 3 — Idempotency check:**
  - Queries escalation rows for `(session_id, task_id, class, idempotency_key)`. If a matching row exists and its status is `Pending` or `Approved` → returns `Ok(EscalationResponse::AlreadyPending { escalation_id })` without creating a duplicate row.

  **Step 4 — Write escalation row:**
  - Inserts `{ escalation_id: Uuid::new_v4(), session_id, task_id, class, requested_scope, justification, idempotency_key, status: Pending, submitted_at: now(), timeout_at: now() + ctx.policy.escalation_timeout() }`.

  **Step 5 — Audit and notify:**
  - Emits `AuditEventKind::EscalationSubmitted { escalation_id, session_id, task_id, class, requested_scope_summary }`.
  - Triggers `notifications::dispatch(event_kind, payload)` — looks up the route for `EscalationSubmitted` in the loaded `PolicyBundle.notifications` (per [`cli-readonly.md`](cli-readonly.md) §5.6), picks the channel set (route-specific OR `default_channels`), and dispatches a per-channel `notify` call. Each channel handler runs in its own `tokio::spawn` so a slow handler cannot block the kernel commit path. **Non-fatal:** any handler that fails emits a `NotificationDeliveryFailed { channel_id, event_kind, reason }` audit event; the escalation row still commits. Handler failure NEVER aborts the parent transaction. The default V1 channel is **Shell** (writes to `<data_dir>/notifications/inbox.jsonl`); operators view notifications via `raxis inbox` ([`cli-readonly.md`](cli-readonly.md) §5.5.16). The V2 surface adds `Email` (SMTP submission) and `Sidecar` (HTTP POST → operator-run translator → Slack / PagerDuty / Teams / ...).  The V1-draft `Webhook` kind was folded into `Sidecar` in V2.5 (forward-only — ).

  **Step 6 — Return:**
  - Returns `Ok(EscalationResponse::Submitted { escalation_id, timeout_at })`.

**`EscalationResponse` variants:** `Submitted { escalation_id, timeout_at }` | `AlreadyPending { escalation_id }` | `Rejected { reason: EscalationErrorCode }`.

**`EscalationErrorCode` variants:** `RateLimitExceeded` | `LineageQuarantined`. These are the only cases where a well-formed escalation request from an authenticated session is turned away as an `Ok(Rejected)` response. `InvalidTask` (step 2) and bad-class deserialization errors (step 1, serde) produce `Err(HandlerError::...)` — transport-level failures, not escalation-level rejections — and are not `EscalationErrorCode` variants.

---

#### Escalation FSM

**States and transitions.** The escalation FSM owns the lifecycle of every escalation from planner submission to terminal resolution. All transitions are kernel-recorded or operator-recorded; the planner cannot drive any transition beyond the initial submission.

**State inventory:**

| State | Terminal? | Description |
|---|---|---|
| `Pending` | No | Submitted by planner; awaiting operator action. No authority change. |
| `Approved` | No | Operator issued a signed `ApprovalToken` via CLI. Token not yet presented. |
| `Denied` | Yes | Operator explicitly denied via `raxis-cli escalation deny <escalation_id>`. No authority change. |
| `TimedOut` | Yes | `timeout_at` elapsed without operator action. Kernel timeout sweep fires. |
| `TokenExpired` | Yes | Token issued (`Approved`) but `valid_until` elapsed before planner presented it. |
| `Consumed` | Yes | Token presented, validated, and the escalated action executed successfully. |

**Transitions:**

| From | To | Trigger | Actor | Audit event |
|---|---|---|---|---|
| *(none)* | `Pending` | `EscalationRequest` received and written | Planner (IPC) | `EscalationSubmitted` |
| `Pending` | `Approved` | `raxis-cli escalation approve <escalation_id> --scope <…> --max-uses <n> --valid-for <secs>` | Operator (CLI) | `EscalationApproved { escalation_id, approval_id }` |
| `Pending` | `Denied` | `raxis-cli escalation deny <escalation_id> [--reason <…>]` | Operator (CLI) | `EscalationDenied { escalation_id, denied_by }` |
| `Pending` | `TimedOut` | Kernel timeout sweep: `now() > timeout_at` | Kernel (sweep) | `EscalationTimedOut { escalation_id }` |
| `Approved` | `Consumed` | `validate_approval_token` returns `Valid`; action executes; `ApprovalProof` written | Kernel (on use) | `ApprovalConsumed { approval_id, escalation_id, action_id }` |
| `Approved` | `TokenExpired` | Kernel timeout sweep: `now() > token.valid_until` | Kernel (sweep) | `ApprovalTokenExpired { approval_id, escalation_id }` |

**Invalid transitions (kernel must reject):**

- Any transition from a terminal state (`Denied`, `TimedOut`, `TokenExpired`, `Consumed`) — escalation rows are immutable once terminal.
- `Pending → Consumed` without passing through `Approved` — a token cannot be consumed without being issued.
- `Approved → Approved` — re-issuing a token for the same escalation creates a new `ApprovalToken` but does not change the escalation state. If the operator re-signs (e.g. extending the expiry), the old token is revoked via `authority::revoke_approval` before the new token is issued.

**Trust invariants (all must hold; violation is a critical trust failure):**

- **INV-ESC-01:** No transition from `Pending` to `Approved` without an operator-signed `ApprovalToken`. The kernel cannot self-approve an escalation.
- **INV-ESC-02:** `validate_approval_token` always checks `token.policy_epoch == ctx.policy.load().epoch()`. If they differ, returns `ApprovalStatus::EpochMismatch` and the escalation remains `Approved` (the token is invalid; the operator must re-issue). The action does not execute.
- **INV-ESC-03:** `token.session_id` must equal the session presenting the token. A token issued for session A cannot be used by session B.
- **INV-ESC-04:** The nonce in each `ApprovalToken` is single-use. `validate_approval_token` checks the nonce against a consumed-nonce table in the store before marking `Valid`. Once consumed, the nonce is written to the table and future presentations of the same token return `NonceConsumed`.
- **INV-ESC-05:** The proposed action must fall within the bounds of `token.scope` — that is, `action ⊆ scope`. This is enforced by `check_scope(&token.scope, action) -> bool` (step 6 of `validate_approval_token`): `true` = action is within scope; `false` = action exceeds scope. `validate_approval_token` maps `false` to `Ok(ApprovalStatus::ScopeMismatch)`. A token scoped to `CapabilityUpgrade { WriteCode }` does not authorize `CapabilityUpgrade { WriteSecrets }`; `check_scope` returns `false` and the caller receives `ScopeMismatch`.
- **INV-ESC-06:** The planner cannot query escalation status by `escalation_id` via IPC in v1 — no status-query endpoint exists in `handlers/mod.rs`. The planner receives `escalation_id` in `EscalationResponse::Submitted` and must re-attempt the intent with the approval token when one is obtained; notification is out-of-band — the v1 default routes `EscalationApproved` events to the Shell notification channel (`<data_dir>/notifications/inbox.jsonl`), and the operator's surrounding tooling (or a `raxis inbox -f` watcher) signals the planner to retry. See [`cli-readonly.md`](cli-readonly.md) §5.6 for the channel routing model. **Testable assertion:** `handlers/mod.rs` must contain no arm matching an escalation-status-query variant in v1; any such arm is a scope violation.

**`validate_approval_token` — canonical contract** (this is the normative spec; the `authority/approval.rs` section below is the implementation home and references this check sequence):

```rust
pub fn validate_approval_token(
    token: &ApprovalToken,
    action: &ProposedAction,   // what the kernel is about to do
    ctx: &KernelContext,
) -> Result<ApprovalStatus, AuthorityError>
```

**Return type semantics:** `Err(AuthorityError)` means the token payload is not usable for policy decisions — the caller must stop without branching on payload fields. Two cases:
- `Err(AuthorityError::SignatureInvalid)` — step 1 crypto failure; the payload may have been tampered with.
- `Err(AuthorityError::ApprovalRevoked)` — pre-step: `approval_id` appears in the revocation set; the token has been administratively invalidated regardless of signature.

`Ok(ApprovalStatus::*)` is returned for all other outcomes, including rejections; callers branch on the `Ok` value to decide whether to proceed.

Check sequence (fail-closed; each step runs only if the previous returned `Ok`):
0. Revocation check: query revocation set for `token.approval_id`. If present → `Err(AuthorityError::ApprovalRevoked)`. No further checks run.
1. Ed25519 signature verification: `ed25519_verify(issuer_pubkey, token_payload_bytes, token.signature)`. `issuer_pubkey` looked up from `ctx.policy.operator_entry(token.issued_by).public_key`. On failure → `Err(AuthorityError::SignatureInvalid)`. No further checks run.
2. Epoch check: `token.policy_epoch == ctx.policy.load().epoch()`. On mismatch → `Ok(ApprovalStatus::EpochMismatch)`.
3. Expiry check: `token.scope.valid_until > now()`. On failure → `Ok(ApprovalStatus::Expired)`.
4. Nonce check: store query for `token.nonce` in consumed-nonce table. If present → `Ok(ApprovalStatus::NonceConsumed)`.
5. Session check: `token.session_id == action.session_id`. On mismatch → `Ok(ApprovalStatus::ScopeMismatch)`.
6. Scope check: `check_scope(&token.scope, action)` — verifies `action ⊆ token.scope`. On failure → `Ok(ApprovalStatus::ScopeMismatch)`.
7. All checks pass → `Ok(ApprovalStatus::Valid)`.

After `Valid` is returned: the caller writes the `ApprovalProof`, marks the escalation `Consumed`, writes the nonce to the consumed-nonce table, and executes the action. These four writes must be atomic (wrapped in a store transaction); if the transaction fails, the action does not execute and the escalation reverts to `Approved`.

**Probe-rate-limiter parameters** (in policy artifact — amendment to Gap 2 schema):

```toml
[escalation_policy]
timeout_secs         = 3600   # u64; how long a Pending escalation waits before TimedOut
window_secs          = 300    # u64; rolling window for per-lineage rate limiting
max_per_window       = 5      # u32; max escalation submissions per lineage per window
quarantine_threshold = 3      # u32; rate-limit trigger count before lineage quarantine
```

These four fields are added to `PolicyBundle` with accessors:
- `pub fn escalation_timeout(&self) -> Duration`
- `pub fn escalation_window(&self) -> Duration`
- `pub fn escalation_max_per_window(&self) -> u32`
- `pub fn escalation_quarantine_threshold(&self) -> u32`

Unknown or missing `[escalation_policy]` block → `PolicyError::MalformedArtifact` (all four fields required; no safe default).

**Task state during `Pending` escalation.** The task is NOT moved to a new state when its escalation is `Pending`. The task retains whatever state it was in when the planner submitted the escalation (typically `GatesPending` for a claim gap, or `Admitted` for a capability gap). The escalation is orthogonal to the task state — it is the planner's request for operator resolution. When the operator approves and the token is issued, the planner presents the token on the next intent attempt and the kernel proceeds with the escalated authority. No `BlockReason::EscalationPending` is written; the task does not transition to `BlockedRecoveryPending` solely due to an open escalation.

---

###### `src/ipc/handlers/proposal_append.rs` — [NEW]


**Purpose:** Handles `ProposalEvent` append requests from the planner. The planner is permitted to append only `ProposalEvent` variants (`PlanProposed`, `IntentSubmitted`, `AmendmentProposed`) — no authority-class events. This handler enforces that restriction by type.

**Why it is named `proposal_append`, not `audit_append`:** The name `audit_append` implied the planner could append general audit events. `proposal_append` names the function correctly: it appends only planner-proposal-class events. The kernel's own authority events are written directly by kernel subsystems through `raxis-audit-tools`, not through IPC.

**What it contains:**
- `pub async fn handle(event: ProposalEvent, session: ValidatedSession, ctx: &HandlerContext) -> Result<AppendAck, HandlerError>`
- Validates that `event` is a `ProposalEvent` variant — enforced by the Rust type system (the handler only accepts `ProposalEvent`, not `AuditEvent`). No runtime check needed.
- Validates that `session.role` is `Role::Planner` — if somehow a non-planner session submits to this endpoint, `HandlerError::Unauthorized` is returned.
- Calls `raxis-audit-tools::writer::append(ProposalAuditEvent::from(event))`. The `From<ProposalEvent>` implementation is the **only** conversion path from `ProposalEvent` to an audit-writable type; it is implemented to produce only `AuditEventKind::Proposal*` variants and panics at compile time (via exhaustive match) if a new `ProposalEvent` variant is added without a corresponding `Proposal*` audit kind. This is the structural guarantee that a planner-submitted event cannot produce an authority-class audit record. The planner never holds a file handle; the kernel serializes the append.
- Returns `AppendAck::Accepted { event_id }`.

---

###### `src/ipc/handlers/operator.rs` — [NEW] — Operator IPC dispatcher (operator UDS only)

**Purpose:** Single dispatcher for every `OperatorRequest` variant arriving on the operator UDS (`<data_dir>/sockets/operator.sock`). Every variant flows through one common pre-handler pipeline (challenge-response auth → `permitted_ops` check → trace-span attach → per-handler call) and produces exactly one `OperatorResponse` reply on the same connection. Each per-variant handler delegates to the appropriate domain module (`authority::session`, `authority::delegation`, `initiatives::lifecycle`, `recovery`, `policy_manager`); this file is the thin adapter layer that maps wire types to domain calls and wraps domain errors into the `OperatorResponse::Error { code, detail }` envelope normatively defined in [`peripherals.md`](peripherals.md) §3 "Operator socket".

**Why a single dispatcher, not one file per variant:** the operator IPC surface is small (13 variants in v1) and every variant shares the same auth pipeline. Splitting into 13 files would obscure the shared envelope-mapping logic and force readers to chase imports to verify the auth flow is consistent. The 13 per-variant handlers are inner `async fn`s in this one file.

**Common pre-handler pipeline (run by `dispatch` for every request):**
1. Read one `OperatorRequest` frame from the connection (per [`peripherals.md`](peripherals.md) §3 wire codec).
2. The connection is already authenticated — challenge-response ran at connect time, and the per-connection state holds `authenticated_operator: AuthenticatedOperator { fingerprint, permitted_ops, op_token }`. The dispatcher extracts the variant name from the request enum tag.
3. **`permitted_ops` gate** — if `authenticated_operator.permitted_ops` does not contain the operation name (matching the `permitted_ops` column in the §2.5.5 IPC discriminant table), return `OperatorResponse::Error { code: UNAUTHORIZED, detail: OperationNotPermitted { operator_id: authenticated_operator.fingerprint, attempted_op: variant_name } }` immediately. No domain call is made; no row is written.
4. Attach a `tracing` span with `operator_id`, `op = variant_name`, `request_id = Uuid::new_v4()`. Every audit row written by the domain handler will inherit this span and so the audit log carries the operator identity and request id even though those fields are not part of every audit event payload.
5. Invoke the per-variant handler (one of the inner `async fn`s below). The handler returns `Result<OperatorResponse, HandlerError>`; the dispatcher converts `Err(HandlerError::*)` into the appropriate `OperatorResponse::Error` and writes one reply frame.

**Per-variant handlers (inner `async fn`s):**

- `async fn handle_create_initiative(req, session, ctx) -> Result<OperatorResponse, HandlerError>`
  - Calls `initiatives::lifecycle::create_initiative(req.plan_toml_path, req.plan_sig_path, &ctx.store, &ctx.policy, &ctx.audit, &ctx.operator_id)`. On success returns `OperatorResponse::InitiativeCreated { … }`. Domain errors map to existing `PlannerErrorCode`-equivalent codes documented in [`kernel-core.md`](kernel-core.md) initiative subsystem.

- `async fn handle_approve_plan(req, session, ctx) -> Result<OperatorResponse, HandlerError>` — wrapper over `initiatives::lifecycle::approve_plan`. Returns `PlanApproved`.

- `async fn handle_reject_plan(req, session, ctx) -> Result<OperatorResponse, HandlerError>` — wrapper over `initiatives::lifecycle::reject_plan`. Returns `PlanRejected`.

- `async fn handle_create_session(req, session, ctx) -> Result<OperatorResponse, HandlerError>`
  1. **Role gate** — if `req.role != Role::Planner`, return `OperatorResponse::Error { code: FAIL_ROLE_NOT_OPERATOR_CREATABLE, detail: RoleNotOperatorCreatable { requested_role: req.role } }`. Gateway sessions are minted by `kernel_core::startup::spawn_gateway`; verifier sessions by `gates::verifier_runner::spawn_verifier`. Neither is operator-creatable.
  2. **Worktree containment check** — if `req.worktree_root.is_none()`, reject (`FAIL_WORKTREE_OUTSIDE_ALLOWED_ROOTS` with empty `allowed_roots` list — defensive, never expected on the wire because the CLI requires `--worktree-root`). Otherwise canonicalise the path (`std::fs::canonicalize`) and verify it is **at, or under**, at least one of `policy.sessions.allowed_worktree_roots`. The "under" relation is **component-aware**, never raw byte-prefix: if the operator allows `/srv/work`, then `/srv/work` and `/srv/work/<anything>` are accepted, but `/srv/work_secret` is rejected. The reference implementation lives in `raxis_policy::PolicyBundle::worktree_root_allowed`, which strips a single trailing `/` from each policy entry then requires either exact equality with the candidate path OR that the next byte after the policy entry in the candidate be `/`. Failure → `FAIL_WORKTREE_OUTSIDE_ALLOWED_ROOTS { worktree_root, allowed_roots }`.
  3. **Lineage parse check** — `Uuid::parse_str(&req.lineage_id.as_str())`. Parse failure → `FAIL_INVALID_LINEAGE_ID { offending_value: req.lineage_id.into_inner(), parse_error: parse_err.to_string() }`. The kernel performs no further semantic check on the value (operator owns the lineage namespace per [`kernel-store.md`](kernel-store.md) §2.5.5 "Lineage ownership and supply"). The parsed value is passed through to the `sessions.lineage_id` column verbatim in its hyphenated UUID form.
  4. **Base ref resolution** — if `req.base_tracking_ref.is_some()`, run `git -C <worktree_root> rev-parse --verify <ref>^{commit}` (the `^{commit}` peel is mandatory — it converts annotated tags to their commit OID and rejects non-commit objects). On non-zero exit → `FAIL_BASE_REF_UNRESOLVED { ref_string, worktree_root, git_stderr }`. Otherwise capture the resolved 40-char hex into `base_sha: Option<CommitSha>`. When `base_tracking_ref.is_none()`, default to `refs/heads/main` per `authority::session::create_session`'s normative default and resolve it the same way; missing `refs/heads/main` is `FAIL_BASE_REF_UNRESOLVED` with `ref_string = "refs/heads/main"`.
  5. **Mint** — call `authority::session::create_session(Role::Planner, Some(worktree_root), base_sha, base_tracking_ref, req.lineage_id, &ctx.session_config, &ctx.store)`. The canonical helper signature takes `lineage_id: LineageId` as a required parameter (matching the `NOT NULL` column in Table 4). On success the call returns `(session_id, session_token_bytes)` where `session_token_bytes: [u8; 32]`. The handler writes `AuditEventKind::SessionCreated { session_id, role: Planner, worktree_root, base_sha, base_tracking_ref, lineage_id: req.lineage_id, created_by_operator: ctx.operator_id, bound_task_id: req.task_id, session_token_sha256: sha256(&session_token_bytes) }` to the audit chain (the SHA-256 of the token is stored, never the raw token).
  6. **Optional task binding** — if `req.task_id.is_some()`, the handler additionally writes `sessions.bound_task_id = Some(task_id)` in the same store transaction as the session insert (via an extension parameter to `create_session` or a follow-up `UPDATE` inside the same transaction; the implementation chooses, but the write MUST be atomic with the session insert so a partial failure does not leave a session whose binding state is undefined). Validates that the task exists and is in `Admitted` state; otherwise `FAIL_INVALID_TASK_STATE { task_id, current_state }`.
  7. **Reply** — return `OperatorResponse::SessionCreated { session_id, session_token: hex(session_token_bytes), role: Planner, worktree_root: Some(worktree_root), base_sha, base_tracking_ref, expires_at: now() + ctx.session_config.default_ttl, bound_task_id: req.task_id, lineage_id: req.lineage_id }`. The token is sent in clear over the operator UDS — this is acceptable because the operator UDS is `mode 0600` and bound to the operator OS user, so only the operator can read the reply.

- `async fn handle_revoke_session(req, session, ctx) -> Result<OperatorResponse, HandlerError>`
  1. **Lookup** — call `authority::session::get_session(req.session_id, &ctx.store)`. `SessionNotFound` → `OperatorResponse::Error { code: FAIL_SESSION_NOT_FOUND, detail: SessionNotFound { session_id: req.session_id } }`.
  2. **Idempotency** — if the row's `revoked_at IS NOT NULL`, return `OperatorResponse::Error { code: FAIL_SESSION_ALREADY_REVOKED, detail: SessionAlreadyRevoked { session_id, revoked_at } }`. (The CLI exits non-zero in this case so orchestration scripts notice; the underlying state is the desired one, but the operator gets a clear "this was already done" signal rather than a false-positive "I just did it".)
  3. **Revoke** — call `authority::session::revoke_session(req.session_id, &ctx.store, &ctx.audit)` which executes the conditional `UPDATE … WHERE revoked_at IS NULL` inside one store transaction (INV-STORE-02) and writes `AuditEventKind::SessionRevoked { session_id, revoked_by_operator: ctx.operator_id, revoked_at }` to the audit chain.
  4. **Reply** — `OperatorResponse::SessionRevoked { session_id, revoked_at }`.
  5. **In-flight effect** — see [`cli-ceremony.md`](cli-ceremony.md) §`session revoke` for the operator-facing behaviour. The handler does not asynchronously close the planner's open connection; the next IPC frame on that connection is rejected by `ipc/auth.rs::validate` reading the now-revoked session row.

- `async fn handle_grant_delegation(req, session, ctx) -> Result<OperatorResponse, HandlerError>`
  - Builds `GrantDelegationRequest` from the wire form, calls `authority::delegation::grant_delegation(req, &ctx.store, &ctx.policy, &ctx.audit)` (full five-step contract in the `authority/delegation.rs` section above), and maps the returned `DelegationId` (or `AuthorityError`) into `OperatorResponse::DelegationGranted { … }` (or `OperatorResponse::Error { code, detail }` per the wire-string code table in [`peripherals.md`](peripherals.md) §3 "Operator socket").

- `async fn handle_retry_task(req, session, ctx) -> Result<OperatorResponse, HandlerError>` — wrapper over `initiatives::lifecycle::retry_task`. Maps `LifecycleError::TaskNotFailed { current_state }` → `FAIL_TASK_NOT_RETRYABLE { TaskNotRetryable { current_state } }`; `LifecycleError::InitiativeTerminal { initiative_state, terminal_criteria }` → `FAIL_INITIATIVE_TERMINAL { InitiativeTerminal { … } }`. Returns `TaskRetried`.

- `async fn handle_resume_task(req, session, ctx) -> Result<OperatorResponse, HandlerError>` — wrapper over `recovery::resume_task`. Maps `RecoveryError::TaskNotInRecoveryPending { current_state }` → `FAIL_TASK_NOT_RESUMABLE { TaskNotResumable { current_state } }`. Returns `TaskResumed`.

- `async fn handle_abort_task(req, session, ctx) -> Result<OperatorResponse, HandlerError>` — wrapper over `initiatives::lifecycle::abort_task`. Returns `TaskAborted`.

- `async fn handle_abort_initiative(req, session, ctx) -> Result<OperatorResponse, HandlerError>` — wrapper over `initiatives::lifecycle::abort_initiative`. Returns `InitiativeAborted`.

- `async fn handle_approve_escalation(req, session, ctx) -> Result<OperatorResponse, HandlerError>` — wrapper over `authority::escalation::approve_escalation`. Returns `EscalationApproved { escalation_id, approval_token_id, approval_token_raw, expires_at }`. The kernel mints `approval_token_raw` (32 CSPRNG bytes, hex-encoded) and stores ONLY `sha256(raw)` in `approval_tokens.token_hash`; the operator passes the raw token to the planner out-of-band, and the kernel re-derives the hash on subsequent intent presentations (kernel-store.md §2.5.5 Table 9 `token_hash` column). The signing input is the canonical UTF-8 byte sequence `"approval|<escalation_id>|<capability_class>|<max_uses>|<valid_for_seconds>"` — the kernel and CLI MUST agree on this exact byte layout (regression-pinned by `authority::escalation::tests::canonical_signing_input_byte_layout`).

- `async fn handle_deny_escalation(req, session, ctx) -> Result<OperatorResponse, HandlerError>` — wrapper over `authority::escalation::deny_escalation`. Returns `EscalationDenied { escalation_id, denied_at }`. No `approval_tokens` row is written (denial creates no durable approval artifact — the audit event is the only record). The optional `reason` field is capped at 512 characters at the dispatcher level (cap pinned by `ipc::operator::escalation_dispatch_tests::deny_escalation_rejects_reason_over_512_chars_before_touching_store`).

- `async fn handle_rotate_epoch(req, session, ctx) -> Result<OperatorResponse, HandlerError>` — wrapper over `policy_manager::advance_epoch`. Returns `EpochAdvanced`. The four-phase contract is fully specified in `policy_manager.rs`; this handler does no additional validation.

**Audit on permitted_ops failure.** The pre-handler `permitted_ops` gate (step 3) appends `AuditEventKind::OperatorOperationDenied { operator_id, attempted_op, reason: NotInPermittedOps, attempted_at }` before returning the `UNAUTHORIZED` response — operator over-reach attempts are forensically visible even though no domain handler ran.

---

##### VCS Subsystem

---

###### `src/vcs/mod.rs` — [NEW]

Re-exports `diff::touched_paths` and `diff::is_ancestor`. No logic.

---

###### `src/vcs/diff.rs` — [NEW] — Provides INV-07 input for `gates/claim.rs`

**Purpose:** Resolves a commit range `(base_sha, head_sha)` to a sorted, stable list of all file paths touched between those two commits. This is the authoritative input to `gates/claim.rs` — single-commit diffs and planner-supplied path manifests are both rejected.

**Why range diff, not `git diff-tree`:** `diff-tree <sha>` answers "what changed in this one commit vs its parent" — under-inclusive for multi-commit branches and wrong for merge commits (returns only merge-resolution deltas, not the union of both sides). `git diff <base> <head> --name-status --no-renames` (the normative form; see §2.5.8) answers "all files changed between these two tree states" for any intent type. **§2.5.8 is the canonical authority for all `vcs::diff` invocations**; the description here is a context note, not a specification.

**`..` vs `...` (two-dot vs three-dot):** v1 uses two-dot. With the ancestor check enforced in `intent.rs`, `base` is always a true ancestor of `head`, so two-dot gives exactly "what the agent added on this branch" — deterministic and auditable. Three-dot (symmetric difference from merge-base) diverges when both sides have advanced and is not used.

**Why git CLI subprocess, not libgit2:** libgit2 is a C binding that expands the unsafe surface and requires independent security tracking. The git CLI stdout format is stable, documented, and deterministic; a subprocess failure is a normal `io::Error`.

**What it contains:**
- `pub fn touched_paths(base_sha: &CommitSha, head_sha: &CommitSha, worktree_root: &Path) -> Result<Vec<PathBuf>, VcsError>`
  - **Normative command (see §2.5.8 for full spec):** `git -C <worktree_root> diff <base_sha> <head_sha> --name-status --no-renames`. Note: space-separated SHAs (not `..` range syntax); `--no-renames` is mandatory; `--name-status` is required for the status-code dispatch table. The timeout wrapper (v1 default: 30s; configurable via `vcs.diff_timeout_secs` with a hard cap, e.g. 120s) applies to this invocation.
  - Reads stdout line by line; sorts result with `paths.sort()` before returning — stable ordering required for INV-05 reproducibility (identical `Vec<PathBuf>` for the same `(base_sha, head_sha)` pair).
  - `worktree_root` is the agent's git worktree path, bound to the session at creation time and validated at startup via `git -C <worktree_root> rev-parse --git-dir`. Concurrent agents operate on distinct `worktree_root` paths. The root is logged in every intent audit event.
  - On timeout or non-zero exit: `VcsError::DiffFailed` with stderr captured.
  - On `worktree_root` validation failure at startup: `BOOT_ERR_VCS_ROOT` (exit code 17).
  - Does NOT resolve branch refs — receives only validated `CommitSha` newtypes (40-char hex); branch refs rejected upstream in `handlers/intent.rs`.

- `pub fn is_ancestor(base_sha: &CommitSha, head_sha: &CommitSha, worktree_root: &Path) -> Result<bool, VcsError>`
  - Spawns `git -C <worktree_root> merge-base --is-ancestor <base_sha> <head_sha>`.
  - Maps exit code 0 → `Ok(true)`, exit code 1 → `Ok(false)`, any other exit → `Err(VcsError::GitError)`.
  - Called by `intent.rs` before `touched_paths`; `Ok(false)` results in `HandlerError::InvalidShaRange` — the intent is rejected.

- `pub fn rev_parse_parent(head_sha: &CommitSha, worktree_root: &Path) -> Result<CommitSha, VcsError>`
  - **Normative command.** Spawns `git -C <worktree_root> rev-parse --verify <head_sha>^1` (note `^1`, not bare `^` — `^1` is unambiguous "first parent" syntax; bare `^` is a synonym but `^1` documents intent and is the form the `topology_check` rev-list command also uses for first-parent semantics). The `--verify` flag makes git exit non-zero with a clear stderr message if the ref does not resolve to a commit object, instead of printing the literal input back. Stdout on success is exactly one 40-char hex commit SHA followed by a newline; the function strips the newline and constructs a `CommitSha` newtype (which validates the 40-char-hex shape on construction).
  - **Called by** `handlers/intent.rs` when `intent_kind == IntentKind::SingleCommit` **and** `base_sha != head_sha` to confirm `base_sha` equals the true first parent of `head_sha`; mismatch → `HandlerError::InvalidShaRange`. Skipped when `base_sha == head_sha` (empty range — see Part 2.4 `handlers/intent.rs`).
  - **Edge case — root commit (no parent).** If `head_sha` is a root commit, `git rev-parse --verify <head_sha>^1` exits non-zero with stderr `fatal: ambiguous argument '<head_sha>^1': unknown revision or path not in the working tree`. The function maps this to `VcsError::HeadIsRootCommit` and the intent handler maps it to `HandlerError::InvalidShaRange` (a root commit cannot have a `base_sha` distinct from itself, so the planner has misrepresented the range).
  - **Edge case — merge commit (multiple parents).** If `head_sha` is a merge commit, `^1` selects the **first parent** specifically (this is intentional — the topology check at `handlers/intent.rs` step 2A rejects `SingleCommit` ranges containing any merge commit *before* `rev_parse_parent` is called, so this case is unreachable for `SingleCommit` intents in practice). The `^1` form is defensive: even if a future code path bypassed the topology check and reached this function with a merge `head_sha`, the result would be deterministic (first parent) rather than git's "ambiguous" error from a bare `<head_sha>^` against multi-parent commits in older git versions. The handler still relies on the topology check as the primary defence for `SingleCommit`.
  - **Edge case — `head_sha` does not exist.** If the SHA is well-formed (40-char hex) but the object is not in the worktree's repository (e.g. operator misconfigured `worktree_root`, or planner submitted a SHA from a different repo), `git rev-parse --verify` exits non-zero with `fatal: Needed a single revision`. The function maps this to `VcsError::ShaNotFound` and the handler maps it to `HandlerError::InvalidShaRange`. This is distinct from `VcsError::GitError` (which is for unexpected git failures: SIGSEGV, missing binary, permission errors, etc.).
  - **Module location.** Lives in `src/vcs/diff.rs` alongside `topology_check`, `is_ancestor`, `touched_paths`, and `compute` — the four functions form one cohesive subprocess wrapper module. A separate `src/vcs/rev_parse.rs` would split a six-line function into its own file with no benefit; cross-function changes (e.g. tightening the timeout or upgrading the SHA validation) are easier to keep coherent in one file.
  - **Timeout.** Same wrapper as `touched_paths` (`vcs.diff_timeout_secs`, default 30s, hard cap 120s). On timeout → `VcsError::GitError { kind: Timeout }`.

- `pub fn topology_check(base_sha: &CommitSha, head_sha: &CommitSha, worktree_root: &Path) -> Result<(), VcsDiffError>`
  - **Added by §2.5.8.** Spawns `git -C <worktree_root> rev-list <base_sha>..<head_sha> --min-parents=2 --count`. If count > 0, returns `Err(VcsDiffError::MergeCommitInRange { merge_count })`. Not called for `IntentKind::IntegrationMerge` — see §2.5.8 §Integration merge carve-out.

- `pub fn compute(base_sha: &CommitSha, head_sha: &CommitSha, worktree_root: &Path) -> Result<Vec<PathBuf>, VcsDiffError>`
  - **Added by §2.5.8.** Wrapper around the normative `git diff <base> <head> --name-status --no-renames` invocation with status-code dispatch and post-processing as defined in §2.5.8 §`vcs::diff` normative specification. Returns sorted `Vec<PathBuf>`. Distinct from `touched_paths` (which predates §2.5.8 and used `--name-only`); `compute` is the canonical function for path scope enforcement. `touched_paths` is retained for INV-07 claim derivation pending alignment with `compute` in a future amendment.

---

> **End of Part 2.2.**
> Part 2.3 covers the authority engine, scheduler/DAG, gate evaluation, provider/fetch routing, prompt assembly, `policy_manager.rs`, `witness_index.rs`, and `breakglass.rs` — with full function signatures for all facade boundaries.

---

##### Multi-Agent VCS Design Note

This note captures the VCS semantics required for the intended concurrent-agent workflow and must be kept consistent with `vcs/diff.rs`, `handlers/intent.rs`, and the `IntentRequest` type in `raxis-types`.

**Concurrent agent workflow**

```text
main ─── A ─── B ─── C                    ← main
               │
               ├─── agent-1 ─── D ─── E   ← agent-1 worktree (base = C, head = E)
               │
               └─── agent-2 ─── F ─── G   ← agent-2 worktree (base = C, head = G)
                                    │
                                    └─── integration ─── H  ← merge commit
```

Git branches persist in `.git/refs` and are shared across all terminals, subprocesses, and reboots. They isolate **history**, not **filesystem state**. Two agents checking out different branches in the same working tree will overwrite each other's files. The required isolation mechanism is `git worktree`: each agent operates from a distinct directory path, all backed by the same `.git` object store.

**Operator contract (v1):** The kernel does not create or manage worktrees. Before starting an agent session, the operator (or orchestration layer) must:
1. Run `git worktree add <worktree_path> <agent_branch>` to create the agent's isolated working directory.
2. Supply `worktree_path` as the `worktree_root` in the session config when creating the planner session with the kernel.
3. Ensure `base_commit_sha` is set to the known-good main-branch tip at branch creation time (not the current main HEAD at intent submission time, which may have advanced).

This contract is enforced by convention in v1; v2 may add kernel-managed worktree lifecycle.

**`IntentRequest` fields (relevant VCS fields)**

| Field | Type | Required | Semantics |
|---|---|---|---|
| `head_commit_sha` | `CommitSha` (40-char hex) | Yes | The commit the agent is asserting as its current work product |
| `base_commit_sha` | `CommitSha` (40-char hex) | Yes | The commit the agent branched from (typically the main tip at branch creation) |

Branch refs (e.g. `main`, `HEAD`, `origin/main`) are rejected by the handler. Both SHAs must be full hex strings; short SHAs are also rejected.

**Claim evaluation for the four intent types**

| Intent type | `base_sha` | `head_sha` | Range semantics |
|---|---|---|---|
| Single-commit work | Parent commit of head (`head^`) | Head commit | Files changed in exactly one commit. **v1 policy hardening**: when `base_sha` is supplied as `head^`, the kernel verifies this claim by running `git -C <worktree_root> rev-parse <head_sha>^` and confirming it equals `base_sha`. If they differ, the intent is rejected — the planner cannot claim single-commit semantics while providing a non-parent base. |
| Multi-commit branch | Main tip at branch creation | Branch head | All files changed across the branch |
| Integration merge | Main tip at session creation (policy-pinned) | Merge commit | Full union of all agent-branch changes |
| PR gate evaluation | Main HEAD at PR creation (policy-pinned) | PR merge commit | All files that would enter main |

**Integration merge commit rule (v1 canonical choice):** The kernel evaluates gate requirements against `git diff <main_head_at_session_creation> <merge_commit> --name-status --no-renames` (normative form per §2.5.8). This gives the true union of all changes from all contributing agent branches. The `main_head_at_session_creation` is locked in `sessions.base_sha` at `create_session` time and cannot be changed by the planner. Two distinct failure modes apply when the integration intent is submitted:

- **Stale base** (`HandlerError::StaleIntegrationBase`): detected by checking `locked_base == current_main_HEAD`. If main has advanced since session creation, this equality fails. The `is_ancestor(locked_base, merge_commit)` check still passes (the locked base remains a valid ancestor of the merge commit), so these are different checks. Remediation: rebase the integration branch on the new main HEAD and resubmit.
- **Ancestor check failed** (`HandlerError::InvalidShaRange`): detected by `is_ancestor(locked_base, merge_commit)` returning false. This means the merge commit does not descend from the locked base — likely a force-push or a corrupted intent. Remediation: verify the merge commit history.

**Why not three-dot (`...`) range:** Three-dot computes the symmetric difference from the merge-base, which diverges when both main and the branch have advanced since branching. Two-dot (`..`) with a kernel-validated base-is-ancestor check gives deterministic, auditable results: the range is exactly "what the agent added," bounded by the operator-supplied base. If the ancestor check fails, the intent is rejected — the planner cannot silently shrink the diff by picking a bad base.

---

### Part 2.3 — Internal Kernel Subsystem Specifications

This part specifies the internal logic layer of the kernel: the six subsystems that implement authority, scheduling, gate evaluation, provider routing, prompt assembly, and the shared store facades. Function signatures here are the locked contract between subsystems; they supersede the illustrative examples in Parts 2.1 and 2.2 wherever there is a conflict — Part 2.3 wins.

**Scope:** `authority/`, `scheduler/`, `gates/`, `provider/`, `prompt/`, `witness_index.rs`, `policy_manager.rs`, `breakglass.rs`.

---

#### Authority Subsystem (`src/authority/`)

**Role:** The authority subsystem is the kernel's trust engine. It owns session lifecycle, delegation checks, verifier run token issuance and consumption, signing key access, and human-issued approval token validation. No other subsystem may read session rows, delegation rows, or key material directly — all access is through this module's public functions.

**Invariant:** Within the kernel binary, `authority` is the designated importer of `raxis-crypto` for all live key operations (HMAC, Ed25519 signing, signature verification). Any kernel module that needs a cryptographic result calls a function in `authority`; it does not link `raxis-crypto` directly. **Controlled exception:** `raxis-audit-tools` is a separate crate with its own direct `raxis-crypto` dependency for chain-hash and JSONL-append operations — it is not a violation of this rule because it is a library crate, not the kernel binary. The rule is: within `raxis` (the kernel crate itself), `authority` is the sole `raxis-crypto` importer. `cargo deny` is configured to enforce this at the per-crate level, not at the workspace level. Policy verification (`registry.authority_keypair.public`) uses the authority keypair, not a separate "quality key" — the quality keypair exists in `KeyRegistry` for quality-gate artifact signing (verifier output attestation) and is documented in the verifier crate spec (Part 3); it is not used in policy signature verification.

---

##### `src/authority/mod.rs` — [NEW]

Re-exports the public API surface of the authority subsystem. Internal sub-modules (`delegation`, `session`, `verifier_token`, `keys`, `approval`) are private to the subsystem; only the functions listed here are callable by other kernel modules.

**Public API re-exported:**
```text
pub use delegation::{check_capability, record_capability_use, list_delegations, mark_stale_on_epoch_advance};
pub use session::{create_session, get_session, revoke_session, update_sequence_number};
pub use verifier_token::{issue_verifier_token, validate_verifier_token, consume_verifier_token};
pub use keys::{verify_hmac, sign_audit_record, authority_pubkey_fingerprint};
pub use approval::{validate_approval_token, revoke_approval};
```

---

##### `src/authority/session.rs` — [NEW]

**Purpose:** Session lifecycle management. A session represents a single authenticated connection from a planner, gateway, or verifier process to the kernel. Sessions are created by the kernel at spawn time, not by the connecting process.

**What it contains:**

- `pub fn create_session(role: Role, worktree_root: Option<PathBuf>, base_sha: Option<CommitSha>, base_tracking_ref: Option<String>, lineage_id: LineageId, config: &SessionConfig, store: &Store) -> Result<SessionId, AuthorityError>`
  - Generates `session_id` (UUID v4) and `session_token` (256-bit CSPRNG random bytes). The token is stored in the `sessions` table and returned to the caller (kernel spawn path). It is **not** derived from `session_id` via HMAC — random generation means session tokens are independently unguessable and can be revoked by deleting/flagging the row without key rotation.
  - For `Role::Planner`: **`worktree_root` must be `Some`** — stores the absolute git worktree path in `sessions.worktree_root` (**NOT NULL**). Runs `git -C <worktree_root> rev-parse --git-dir`; validation failure returns **`AuthorityError::InvalidWorktree`** (kernel spawn maps this to **`BOOT_ERR_VCS_ROOT`** when session creation is part of bootstrap — exit code 17; same operator-facing story as §2.5.8). Records `base_sha` / `base_tracking_ref` per §2.5.1 Table 4. When the spawn path pins a main tip for integration semantics, `base_sha` is the resolved commit OID and **`base_tracking_ref` is the exact symbolic ref that was resolved** (normative default when the operator does not override: `refs/heads/main`). All locked for the session lifetime.
  - For `Role::Gateway` and `Role::Verifier`: **`worktree_root` must be `None`** — stores **SQL NULL** in `sessions.worktree_root`. These roles do not run kernel VCS diff/ancestor/topology on their **own** session row (no range intents). **`base_sha` and `base_tracking_ref` are SQL NULL.** Verifier subprocesses still receive a **`worktree_root` path via the planner session** bound to `task.session_id` when spawned (`spawn_verifier`, witness recheck) — that path is **not** read from the verifier's kernel session row.
  - **`create_session` rejects** `Planner` + `worktree_root: None` and **`Gateway`/`Verifier` + `worktree_root: Some`** at API boundary — no sentinel paths; implementers must not substitute empty strings or the kernel cwd.
  - Writes session row to `sessions` table. Returns `SessionId`.
  - Emits `AuditEventKind::SessionCreated { session_id, role, worktree_root }` — `worktree_root` is present in the payload **only when stored non-NULL** (planner); gateway/verifier omit it or use `Option`/JSON null consistently in the audit schema.

- `pub fn get_session(session_id: &SessionId, store: &Store) -> Result<SessionRow, AuthorityError>`
  - Returns the session row or `AuthorityError::SessionNotFound`. Called by `ipc/auth.rs` during token validation.

- `pub fn revoke_session(session_id: &SessionId, store: &Store, audit: &AuditTools) -> Result<(), AuthorityError>`
  - Sets `revoked_at = now()` in the session row. Subsequent `get_session` calls return `AuthorityError::SessionRevoked`.
  - Emits `AuditEventKind::SessionRevoked { session_id, revoked_by }`.

- `pub fn update_sequence_number(session_id: &SessionId, expected: u64, store: &Store) -> Result<(), AuthorityError>`
  - Atomically increments the stored sequence to `expected + 1`. Returns `AuthorityError::SequenceMismatch` if the current stored value does not equal `expected` — prevents concurrent IPC messages from advancing the sequence out of order.
  - > **Superseded in the IPC path by §2.5.1 INV-01 enforcement.** The IPC dispatcher (`ipc/auth.rs::validate`) does **not** call this function. Instead, it executes `UPDATE sessions SET sequence_number = ?` atomically with the `nonce_cache` INSERT inside the same store transaction (steps 4–5 of the §2.5.1 Table 16 dispatcher sequence). `update_sequence_number` is retained as a store-level utility for non-IPC contexts (test harnesses, crash-recovery reconciliation), but any caller outside those contexts should use the dispatcher auth transaction instead.

---

##### `src/authority/delegation.rs` — [NEW]

**Purpose:** Capability delegation management. A delegation is a kernel-issued record that grants a session a specific `CapabilityClass` for a bounded scope and TTL. Delegations are issued by the operator (via the CLI approval path) and recorded in the kernel store; they are not self-issued by the planner.

**What it contains:**

- `pub fn check_capability(session_id: &SessionId, capability: CapabilityClass, store: &Store) -> Result<DelegationStatus, AuthorityError>`
  - **Pure read. No writes.** Queries the `delegations` table for a record matching `(session_id, capability)` and returns its current status without modifying any row. Safe to call from CLI tooling, operator inspection, logging, dry runs, and metrics — calling it never advances the staleness state.
  - Returns:
    - `DelegationStatus::Active` — record found, TTL not expired, `status = Active`.
    - `DelegationStatus::StaleOnNextUse` — record found, TTL not expired, `status = StaleOnNextUse` (set by `mark_stale_on_epoch_advance`). Returned as-is; the caller decides whether to advance state.
    - `DelegationStatus::RenewalRequired` — delegation was used once in stale state via an enforcement path; not renewed. Acts as a block.
    - `DelegationStatus::Expired` — TTL has passed regardless of epoch.
    - `DelegationStatus::NotGranted` — no record exists for `(session_id, capability)`.
  - Does **not** delete expired delegations; rows are retained for audit purposes.

- `pub fn record_capability_use(session_id: &SessionId, capability: CapabilityClass, store: &Store) -> Result<(), AuthorityError>`
  - **Enforcement hook. Writes.** Called exclusively by `gates/mod.rs::evaluate_claims` at step 4, immediately after all gate types are satisfied (terminal `GateEvalResult::Pass`). Not called on `PendingWitness` — the recheck path detects staleness fresh since the row remains `StaleOnNextUse` until a terminal pass. Atomically transitions the delegation row from `StaleOnNextUse` to `RenewalRequired` for each capability that was stale during this evaluation.
  - Returns `AuthorityError::DelegationNotStale` if the row is not currently `StaleOnNextUse` (guards against double-call or race).
  - **Must not** be called from any non-enforcement path. CLI tools that need to simulate enforcement should call a future `delegation::simulate_consume` (test/admin hook, not this function).

- `pub fn list_delegations(session_id: &SessionId, store: &Store) -> Result<Vec<Delegation>, AuthorityError>`
  - Returns all delegation rows for the session regardless of status. Used by the CLI `gate-verdict` command and by `gates/claim.rs` for delegation context assembly.

- `pub fn mark_stale_on_epoch_advance(store: &Store) -> Result<usize, AuthorityError>`
  - Called by `policy_manager.rs` when the policy epoch advances. Sets `status = StaleOnNextUse` on all `Active` delegation rows. On next `check_capability`, the caller receives `DelegationStatus::StaleOnNextUse` — the delegation still passes for one use but the planner must renew before the following action.
  - Returns the count of rows updated (for audit logging by the caller).

- `pub fn grant_delegation(req: GrantDelegationRequest, store: &Store, policy: &PolicyBundle, audit: &AuditTools) -> Result<DelegationId, AuthorityError>`
  - **Operator-driven write.** Invoked exclusively by `handlers/operator::handle_grant_delegation` after operator IPC challenge-response and `permitted_ops` check ([`kernel-store.md`](kernel-store.md) §2.5.5). The request shape is `GrantDelegationRequest { session_id: SessionId, capability_class: CapabilityClass, delegating_role_id: RoleId, expires_at: UnixSeconds, scope_json: Option<String>, operator_sig: Ed25519Sig }`.
  - **Step 1 — Session validity:** `get_session(session_id)`; reject `SessionNotFound`, `SessionRevoked`, or `SessionExpired` (returns `AuthorityError::SessionInvalid { reason }` mapped by the operator handler to `OperatorErrorCode::FAIL_SESSION_INVALID`).
  - **Step 2 — Policy ceiling check:** Look up `policy.role_ceilings.get(&req.delegating_role_id)`; if absent or the requested `capability_class` is not in the role's ceiling bitmap, return `AuthorityError::CapabilityAboveCeiling { role_id, capability_class }` → `OperatorErrorCode::FAIL_CAPABILITY_ABOVE_CEILING`. This is the kernel-side enforcement of the operator-declared role ceiling — operator policy says "this role may at most grant capabilities X, Y, Z"; the operator cannot exceed it via this IPC.
  - **Step 2.5 — Operator-signature verification (new):** Reconstruct the canonical signing-domain bytes per [`kernel-store.md`](kernel-store.md) §2.5.5 "Delegation grant signing domain on the operator socket" (domain prefix `"RAXIS-V1-DELEGATION-GRANT"` || `0x00`-separated UTF-8 fields, with `expires_at` as 8-byte LE u64 and `scope_json` length-prefixed when present). Compute `signing_input = SHA-256(canonical_bytes)`. Look up the operator's Ed25519 public key from `policy.operator_entry(ctx.operator_fingerprint).public_key`. Run `Ed25519Verify(pubkey, signing_input, req.operator_sig)`. Failure → `AuthorityError::DelegationSignatureInvalid { delegation_id_proposed: <uuid generated for the row but not yet persisted, included for audit only> }` → `OperatorErrorCode::FAIL_DELEGATION_SIGNATURE_INVALID`. **The handler MUST run the policy-ceiling check (step 2) before signature verification** so a malformed signature on an out-of-ceiling capability is surfaced as the simpler ceiling error first (better operator UX); an in-ceiling capability with an invalid signature is the only path to `FAIL_DELEGATION_SIGNATURE_INVALID`.
  - **Step 3 — TTL bounds check:** `req.expires_at` MUST be `> now()` and `<= now() + policy.delegations.max_ttl_seconds` (default 86400 = 24h). Out of range → `AuthorityError::DelegationTtlOutOfRange { requested, max }` → `OperatorErrorCode::FAIL_DELEGATION_TTL_OUT_OF_RANGE`.
  - **Step 4 — Uniqueness check:** Inside the same SQL transaction as step 5, attempt insert; the UNIQUE constraint on `delegations(session_id, capability_class)` filtered to `status IN ('Active', 'StaleOnNextUse')` is the canonical source of truth. A constraint violation maps to `AuthorityError::DelegationAlreadyActive { existing_delegation_id }` → `OperatorErrorCode::FAIL_DELEGATION_ALREADY_ACTIVE`. The operator must `RevokeDelegation` (deferred to v2) or wait for natural expiry before re-granting; v1 has no in-place "renew" path because the rotation semantics around `StaleOnNextUse` would be ambiguous.
  - **Step 5 — Insert and audit (single transaction, INV-STORE-02):** Insert row into `delegations` with `{ delegation_id: Uuid::new_v4(), session_id, capability_class, delegating_role_id, granted_at: now(), expires_at, status: 'Active', epoch_stale_set_at: NULL, scope_json, operator_signature: req.operator_sig.to_bytes() }` (per [`kernel-store.md`](kernel-store.md) §2.5.1 Table 7 with the `operator_signature` column added per §2.5.5 "Delegation grant signing domain"). Append `AuditEventKind::DelegationGranted { delegation_id, session_id, capability_class, delegating_role_id, granted_by_operator: ctx.operator_fingerprint, expires_at, operator_sig_sha256: SHA-256(req.operator_sig) }` to the audit chain (the SHA-256 of the signature goes to the audit, not the raw signature — the raw value lives in `delegations.operator_signature` and is recoverable by joining audit → store on `delegation_id`). `COMMIT`.
  - **Returns** `Ok(delegation_id)` on success; the operator handler wraps it in `OperatorResponse::DelegationGranted { delegation_id, granted_at, expires_at }`.
  - **Idempotency:** none in v1 — operator must not retry a `GrantDelegation` after a transport timeout without first calling `list_delegations` to check whether the prior call landed. A naive retry will get `FAIL_DELEGATION_ALREADY_ACTIVE` if the original landed (safe), but the operator gets no `delegation_id` back from the duplicate. v2 considers an `idempotency_key` field; v1 keeps the wire shape minimal.
  - **Concurrency:** the operator IPC dispatcher serializes operator requests per connection; cross-connection races (two operators granting the same `(session, capability)` simultaneously) are resolved by the UNIQUE constraint — exactly one wins, the other gets `FAIL_DELEGATION_ALREADY_ACTIVE`.

---

##### `src/authority/verifier_token.rs` — [NEW]

**Purpose:** Kernel-issued single-use credentials for verifier subprocess runs. A `verifier_run_token` is issued by `gates/verifier_runner.rs` before spawning the verifier, passed to the verifier via its spawn envelope, and consumed on first valid presentation at `ipc/handlers/witness.rs`. Verifier tokens are stored in a separate table from session tokens.

**What it contains:**

- `pub fn issue_verifier_token(task_id: &TaskId, gate_type: GateType, evaluation_sha: &CommitSha, ttl: Duration, store: &Store) -> Result<VerifierRunToken, AuthorityError>`
  - Generates a 256-bit random token value. Hashes it with SHA-256 and stores `{ verifier_run_id, task_id, gate_type, evaluation_sha, token_hash, issued_at, expires_at, consumed: 0 }` in the `verifier_run_tokens` table. The raw token bytes are never stored; only the hash is persisted. The raw token is returned to the caller for inclusion in the verifier spawn envelope.
  - Returns the `VerifierRunToken` (contains `verifier_run_id` + raw token bytes) to be passed in the verifier's spawn envelope.

- `pub fn validate_verifier_token(verifier_run_id: &VerifierRunId, token_bytes: &[u8], store: &Store) -> Result<VerifierTokenRow, AuthorityError>`
  - Looks up the token by `verifier_run_id`. Computes SHA-256 of `token_bytes` and compares constant-time to `verifier_run_tokens.token_hash`. Returns `AuthorityError::TokenNotFound`, `AuthorityError::TokenMismatch`, `AuthorityError::TokenExpired`, or `AuthorityError::TokenConsumed` as appropriate.
  - Does **not** consume the token — consumption is a separate step called only after the witness body passes all checks in `handlers/witness.rs`.

- `pub fn consume_verifier_token(verifier_run_id: &VerifierRunId, store: &Store) -> Result<(), AuthorityError>`
  - Sets `consumed = 1` and `consumed_at = now()` atomically (`UPDATE verifier_run_tokens SET consumed = 1, consumed_at = now() WHERE verifier_run_id = ? AND consumed = 0`). Returns `AuthorityError::AlreadyConsumed` if `rows_affected() == 0` (double-submission guard).

---

##### `src/authority/keys.rs` — [NEW]

**Purpose:** Cryptographic key access and operations. This is the only module in the kernel binary that holds live key material in memory. All other modules that need HMAC or signing call functions here; they never receive raw key bytes.

**What it contains:**

- `pub struct KeyRegistry { authority_keypair: KeyPair, quality_keypair: KeyPair, verifier_token_key: SymmetricKey }` — loaded once at startup (`step 4`), held in an `Arc<KeyRegistry>` passed through `HandlerContext`. `quality_keypair` is **loaded but not consumed by any v1 code path** — it is held in the registry for forward compatibility with v2 witness-record signing (see [`kernel-store.md`](kernel-store.md) §2.5.4 key inventory `quality_keypair` row for the rationale and v1 integrity story). The v1 kernel must still load it at startup so genesis-time-installed key material is available without a re-ceremony when v2 lands; calling `registry.quality_keypair.sign(...)` from any v1 module is a spec violation and should be caught in code review until the v2 wiring spec is published.

- `pub fn verify_hmac(token_bytes: &[u8], session_id: &SessionId, registry: &KeyRegistry) -> Result<(), AuthorityError>`
  - Computes `HMAC-SHA256(key=registry.authority_keypair.secret, msg=session_id_bytes)` and compares to `token_bytes` in constant time. Returns `AuthorityError::HmacMismatch` on failure.

- `pub fn sign_audit_record(record_bytes: &[u8], registry: &KeyRegistry) -> Signature`
  - Signs `record_bytes` with `registry.authority_keypair` using Ed25519. Used by `raxis-audit-tools::writer` when appending authority-class events.

- `pub fn authority_pubkey_fingerprint(registry: &KeyRegistry) -> String`
  - Returns the hex-encoded SHA-256 fingerprint of the authority public key. Included in genesis record and `KernelStarted` audit event.

---

##### `src/authority/approval.rs` — [NEW]

**Purpose:** Human-issued signed approval tokens. Approval tokens are issued by the operator via the CLI (`raxis-cli escalation approve <escalation_id> --scope <scope> --max-uses <n> --valid-for <seconds>`), signed with the **operator's own private key** (the key from the operator's `[[operators.entries]]` entry in the policy artifact — not the kernel's `authority_keypair`). The kernel validates the token by looking up the operator's public key from `policy.operator_entry(token.issued_by)`. These are distinct from verifier run tokens (kernel-issued, machine-to-machine) and from session tokens (kernel-issued, process authentication).

**What it contains:**

- `pub fn validate_approval_token(token: &ApprovalToken, action: &ProposedAction, ctx: &KernelContext) -> Result<ApprovalStatus, AuthorityError>`
  - Canonical implementation of the 8-step check sequence (step 0 = revocation pre-check, steps 1–7 = FSM section). `Err(AuthorityError)` for unusable token (revoked or bad sig); `Ok(ApprovalStatus::*)` for all other outcomes. See the FSM section for the normative check sequence and return-type semantics.
  - `ProposedAction` and `KernelContext` are defined in `raxis-kernel` — not in `raxis-types`. They are kernel-internal types; the planner has no access to them.
  - Operator public key is sourced from `ctx.policy.operator_entry(token.issued_by).public_key` — never from `registry.authority_keypair.public`.

- `pub fn check_scope(scope: &ApprovalScope, action: &ProposedAction) -> bool`
  - Returns `true` if `action ⊆ scope` — the proposed action falls within every dimension the scope predicate allows. Returns `false` if any dimension of the action exceeds what the token authorized.

- `pub fn revoke_approval(approval_id: &ApprovalId, store: &Store, audit: &AuditTools) -> Result<(), AuthorityError>`
  - Adds `approval_id` to the approval revocation set in the store. Subsequent `validate_approval_token` calls for any token with this `approval_id` return `Err(AuthorityError::ApprovalRevoked)` at step 0 (pre-signature check). This is intentionally an `Err` — same as `SignatureInvalid` — because a revoked token is definitively not usable for policy decisions; callers should not branch on payload fields of a revoked token.
  - Emits `AuditEventKind::ApprovalRevoked { approval_id, revoked_by, revoked_at }`.

---

#### Scheduler Subsystem (`src/scheduler/`)

**Role:** The scheduler is responsible for lane admission, DAG-based task ordering, and concurrency budget enforcement. It does not execute tasks — it decides whether a task may enter the execution pipeline (admission) and in what order ready tasks are surfaced to the planner. All admission decisions are recorded in the audit log.

**Invariant:** The scheduler never calls `gates/`, `authority/`, or `vcs/`. It receives a task record after initial claim evaluation (claims must have passed; witnesses may still be outstanding for `GatesPending` tasks) and makes purely structural decisions: does the lane have budget, and does the DAG allow this task to proceed?

---

##### `src/scheduler/mod.rs` — [NEW]

Re-exports the public admission API.

```text
pub use admit::{admit_in_tx, PlanTask};
pub use dag::{next_ready_tasks, mark_task_complete, transition_to_admitted};  // add_task/insert_edges_in/detect_cycle_in are public for in-tx callers
pub use lane::{lane_config_for_row, get_lane_status};
pub use budget::{check_budget, current_budget};
```

---

##### `src/scheduler/admit.rs` — [NEW]

**Purpose:** Plan-time task instantiation, called exclusively from `initiatives::lifecycle::approve_plan`. Inserts task rows and DAG edges for all tasks defined in a newly approved plan. **`admit` is not called from the intent handler** — budget checking, budget reservation, and gate evaluation all happen on the intent path (`handlers/intent.rs`) using VCS-derived `touched_paths` and `estimated_cost` that do not exist at plan instantiation time.

**What it contains:**

- `pub fn admit_in_tx(conn: &rusqlite::Connection, task: PlanTask, policy_epoch: u64) -> Result<TaskId, SchedulerError>`
  - `conn` is a borrowed `&Connection` so the caller — exclusively `lifecycle::approve_plan` — owns the surrounding transaction and can compose many `admit_in_tx` calls + the `initiatives` UPDATE inside one `BEGIN`/`COMMIT` (kernel-store.md §2.5.1 INV-STORE-02). Passing a raw `Connection` (auto-commit) violates INV-STORE-02 and is forbidden by review.
  - `PlanTask` is a plan-derived struct: `{ task_id: TaskId, initiative_id: InitiativeId, lane_id: LaneId, name: String, dependencies: Vec<TaskId> }`. It does **not** carry `estimated_cost`, `touched_paths`, or `submitted_claims` — those fields are populated on the task row by the intent handler at first intent time, not at plan instantiation time. The `name` field is held for audit-event readability only; the DDL has no `name` column.
  - Validates that `task.lane_id` is a configured lane in the currently loaded policy. Returns `SchedulerError::UnknownLane { lane_id }` if the lane name does not appear in the policy bundle passed to the caller (`approve_plan` provides the loaded `&PolicyBundle`). [Lane validation is currently planned for PR-X; v1 implementation accepts any lane string and relies on intent-time validation.]
  - **Execution order inside the caller's transaction:**
    - Step 1: `dag::detect_cycle_in(conn, task.task_id, &task.dependencies)` — pure read DFS over the in-progress edge set; returns `SchedulerError::CyclicDependency` if the proposed edges would create a cycle. No state written.
    - Step 2: Insert task row into `tasks` with `state = TaskState::Admitted`, `actor = 'kernel'`, `policy_epoch`, `admitted_at = transitioned_at = now`, `actual_cost = 0`. Intent-bound nullable columns (`session_id`, `evaluation_sha`, `base_sha`, `submitted_claims_json`, `block_reason`, `admission_reserved_units`) are inserted as SQL NULL.
    - Step 3: `dag::insert_edges_in(conn, &task.initiative_id, task.task_id, &task.dependencies)` — inserts `(initiative_id, predecessor_task_id, successor_task_id)` rows into `task_dag_edges` now that the task row exists. The `initiative_id` column is required (NOT NULL FK to `initiatives`).
  - Audit emission is performed by the caller (`approve_plan`) **after** `tx.commit()` per kernel-store.md §2.5.2 ("SQLite committed first, JSONL appended second"). `admit_in_tx` itself emits no audit events.
  - Returns `Ok(task_id)` on success.
  - **No `check_budget` and no `consume_budget`.** These are called by the intent handler after gate evaluation, using the VCS-derived `estimated_cost`. `admit_in_tx` does not perform budget operations because the plan does not encode cost per task — cost is computed at intent time from `touched_paths` and `intent_kind`.

---

##### `src/scheduler/dag.rs` — [NEW]

**Purpose:** Directed acyclic graph over tasks within an initiative. A task is "ready" when all its predecessors are in `Completed` state. The DAG is persisted in the `task_dag_edges` table; the in-memory representation is rebuilt on demand from the store (no live DAG object held between requests — avoids state divergence after recovery).

**What it contains:**

- `pub fn add_task(initiative_id: &InitiativeId, task_id: TaskId, dependencies: Vec<TaskId>, store: &Store) -> Result<(), SchedulerError>`
  - Convenience wrapper for callers that own a `&Store` (not a transaction). Acquires the store mutex, calls `detect_cycle_in`, then `insert_edges_in`. Currently unused by production code (kept for forward-compat); production admission goes through `admit_in_tx` which controls its own transaction.

- `pub fn detect_cycle_in(conn: &rusqlite::Connection, new_task: &TaskId, proposed_deps: &[TaskId]) -> Result<(), SchedulerError>`
  - DFS from each proposed dependency following existing predecessor edges in `task_dag_edges`; if `new_task` is reachable from itself, returns `SchedulerError::CyclicDependency`. Bounded to `MAX_DAG_DEPTH = 64` levels to prevent unbounded traversal. **Pure read — writes nothing.** Called by `admit_in_tx` (Step 1) inside the caller's transaction so the cycle check observes any edges inserted earlier in the same transaction (which is essential when admitting a multi-task plan with cross-references).

- `pub fn insert_edges_in(conn: &rusqlite::Connection, initiative_id: &InitiativeId, task_id: &TaskId, dependencies: &[TaskId]) -> Result<(), SchedulerError>`
  - Inserts `(initiative_id, predecessor_task_id, successor_task_id)` rows into `task_dag_edges`. The `initiative_id` column is required (NOT NULL FK per kernel-store.md §2.5.1 Table 6) and identifies which initiative the edge belongs to; the same task_id can never appear in two initiatives, but the column makes per-initiative cleanup queries cheap and explicit. Called by `admit_in_tx` in Step 3, after the task row exists.

- `pub fn next_ready_tasks(initiative_id: &InitiativeId, store: &Store) -> Result<Vec<TaskId>, SchedulerError>`
  - Returns all tasks in `TaskState::Admitted` (not `GatesPending`) whose predecessor edges are all satisfied (`predecessor_satisfied = 1`). Computed by a single SQL query joining `tasks` and `task_dag_edges` (see the `next_ready_tasks` query pattern in §2.5.1 DDL Part 1). `GatesPending` tasks are excluded regardless of predecessor state — they are not executable until a gate-recheck transitions them to `Admitted`.

- `pub fn transition_to_admitted(task_id: &TaskId, store: &Store) -> Result<(), SchedulerError>`
  - Sets `TaskState::GatesPending → TaskState::Admitted`. Returns `SchedulerError::InvalidStateTransition` if current state is not `GatesPending`. Called by `ipc/handlers/witness.rs` after a gate-recheck returns `GateEvalResult::Pass` for all outstanding gates.

- `pub fn mark_task_complete(task_id: &TaskId, store: &Store) -> Result<(), SchedulerError>`
  - Sets `TaskState::Completed` and `completed_at = now()`. Subsequent `next_ready_tasks` calls will surface tasks that depended on this one.

---

##### `src/scheduler/lane.rs` — [NEW]

**Purpose:** Lane configuration and status. A lane is a named execution channel with a concurrency cap and cost ceiling. Lane definitions are part of the signed policy artifact; the scheduler reads but does not write lane configuration.

**What it contains:**

- `pub struct LaneConfig { lane_id: LaneId, max_concurrent_tasks: u32, max_cost_per_epoch: u64, priority: u8 }`

- `pub fn lane_config_for_row(lane_id: &LaneId, policy: &PolicyBundle) -> Result<LaneConfig, SchedulerError>`
  - `policy.lane_config(lane_id).ok_or(SchedulerError::NoLaneAssigned)`. Used wherever the kernel needs lane ceilings for a task row loaded from the store. **`lane_id` on the task row comes from the signed plan artifact**, validated at `approve_plan` / `scheduler::admit` against policy — the intent handler does **not** accept a planner-supplied lane override on `IntentRequest` in v1 (lane is fixed per task at plan approval).

- `pub fn get_lane_status(lane_id: &LaneId, store: &Store) -> Result<LaneStatus, SchedulerError>`
  - Returns current `{ active_tasks: u32, reserved_cost: u64 }` for operator inspection (used by `raxis-cli status` CLI command).

---

##### `src/scheduler/budget.rs` — [NEW]

**Purpose:** Per-lane concurrency and cost budget enforcement. Budget state is persisted in the `lane_budget_reservations` table so it survives kernel restarts. Reservation rows are created on **intent pickup** (`handlers/intent.rs`, after gate evaluation, when transitioning from `Admitted` into `Running` or `GatesPending`) — **not** at `approve_plan` / `scheduler::admit`. They are released on task completion, failure, or abort. Continuation intents on an already-`Running` task **do not** insert another reservation (PK `(lane_id, task_id)`).

**What it contains:**

- `pub fn check_budget(lane_id: &LaneId, estimated_cost: u64, store: &Store) -> Result<(), SchedulerError>`
  - Reads current `{ active_tasks, reserved_cost }` for the lane.
  - Returns `SchedulerError::BudgetExceeded { kind: ConcurrencyLimit }` if `active_tasks >= lane.max_concurrent_tasks`.
  - Returns `SchedulerError::BudgetExceeded { kind: CostLimit }` if `reserved_cost + estimated_cost > lane.max_cost_per_epoch`.
  - Pure read; writes nothing. Called from the intent handler after gate evaluation succeeds, before `consume_budget`.

- `pub fn consume_budget(lane_id: &LaneId, task_id: &TaskId, cost: u64, store: &Store) -> Result<(), SchedulerError>`
  - Inserts a `lane_budget_reservations { lane_id, task_id, reserved_cost: cost, reserved_at }` row. Called from the intent handler transaction, after gate evaluation returns `Pass`, `BreakglassPass`, or `PendingWitness`, and before `transition_task`. Not called from `admit`.

- `pub fn current_budget(lane_id: &LaneId, store: &Store) -> Result<LaneBudgetSnapshot, SchedulerError>`
  - Returns `LaneBudgetSnapshot { active_tasks: u32, reserved_cost: u64 }` for the lane. Alias for `get_lane_status` at the budget layer; re-exported from `scheduler/mod.rs` for callers that only care about budget state without lane configuration details.

- `pub fn release_budget(lane_id: &LaneId, task_id: &TaskId, store: &Store) -> Result<(), SchedulerError>`
  - Issues `DELETE FROM lane_budget_reservations WHERE lane_id = ? AND task_id = ?`. Checks `rows_affected()` from the SQLite result: `0` → reservation already released, return `Ok(())` (idempotent — safe on duplicate call from crash recovery or `reconcile_tasks`); `1` → released, lane credited; `> 1` → return `Err(SchedulerError::CorruptReservationState { task_id })` (schema invariant violation). This makes `release_budget` safe to call from `recovery::reconcile_tasks` and from any terminal-state handler without double-crediting the lane.

- `pub fn compute_admission_cost(touched_paths: &[PathBuf], intent_kind: IntentKind, policy: &PolicyBundle) -> Result<u64, BudgetError>`
  - Calls `policy.base_cost_for_intent_kind(intent_kind)`. If `None` (intent kind absent from cost table) → `Err(BudgetError::UnknownIntentKindCost { intent_kind })`. **No fallback cost is applied.** Unknown intent kinds are rejected at admission, not silently priced at a default. Parallel to `StrictDefault` in `policy_lookup::required_claims`: new surface area fails closed until policy acknowledges it.
  - `base_cost: u64` = the returned value.
  - `path_cost: u64 = touched_paths.len() as u64 * policy.cost_per_touched_path()`. Uses the same sorted, deduplicated `touched_paths` list already derived by `vcs::diff` — no second diff, no independent re-derivation.
  - `raw: u64 = base_cost.saturating_add(path_cost)` — saturating arithmetic; overflow on abnormally large diffs saturates to `u64::MAX` before the cap, not a wrapped small value.
  - Returns `Ok(min(raw, policy.max_cost_per_task()))`.
  - **Pure function** — no store access, no side effects. Inputs are kernel-trusted: `touched_paths` from `vcs::diff`, `intent_kind` used only as a table lookup key (cannot steer the formula), `PolicyBundle` kernel-controlled. The planner cannot influence the result.
  - **Semantics (mandatory for implementers):** the result is "admission units" — not a token count, API cost, or wall-clock estimate. `estimated_cost` is a historical field name; the formula is a deliberate coarse heuristic for lane saturation control. Code that treats this value as a token budget is a misuse.
  - `BudgetError::UnknownIntentKindCost { intent_kind: IntentKind }` — the `intent.rs` handler receives this error and returns `Ok(IntentResponse::Rejected { reason: PlannerErrorCode::FAIL_POLICY_VIOLATION })` directly. This is a policy-shaped planner rejection, not an infrastructure error, so it does **not** flow through `dispatcher::map_error`. No task binding `UPDATE`, no reservation insert, no `transition_task`.

- `pub fn reconcile_actual_cost(task_id: &TaskId, actual_units: u64, source: ActualCostSource, store: &Store, audit: &AuditTools) -> Result<(), BudgetError>`
  - Writes `task.actual_cost = actual_units` to the task row.
  - Let `reserved_units = task.admission_reserved_units.unwrap_or(0)` (set once at first `consume_budget` — see `handlers/intent.rs`; omitted tasks default to 0). If `actual_units > reserved_units` → emits `AuditEventKind::BudgetOverrun { task_id, lane_id, estimated_cost: reserved_units, actual_cost: actual_units, delta: actual_units - reserved_units, planner_reported: source.is_planner_reported() }`.
  - Does **not** retroactively adjust the lane reservation (already released at terminal state before reconciliation runs). Budget overruns are audit signals for operator tuning, not enforcement triggers. **Ordering requirement:** every terminal-state handler must call `release_budget` before `reconcile_actual_cost`; recovery paths (`recovery::reconcile_tasks`) must follow the same ordering for tasks transitioned to `BlockedRecoveryPending`. Reordering these calls would violate the "reservation already released" invariant checked by `rows_affected()`.
  - `ActualCostSource` enum (local to `budget.rs`): `InferenceResponse { inference_id: Uuid }` — authoritative, sourced from gateway-returned provider metadata on the kernel-controlled inference path; `PlannerReported { planner_reported_tokens: u64 }` — observational only, written to the audit record as a `planner_reported_tokens` field, never used to compute enforcement quantities. Consumers of audit `BudgetOverrun` events must filter on `planner_reported = false` to get enforcement-grade data.

**Lane budget and session fetch quota are independent controls.** Lane admission cost (`estimated_cost` units, enforced at `consume_budget`) and session fetch quota (`session.fetch_quota`, enforced per `FetchRequest` at `rate_limit::check_rate_limit`) are independent enforcement axes. Neither implies the other: a task cheap to admit may issue many fetches; an expensive task may issue none. Operators must tune both independently. Exhausting fetch quota does not write a `BlockReason`, does not trigger a lane reservation release, and does not cause a task FSM transition — see Path A semantics in `rate_limit.rs` and `handlers/fetch.rs`.

---

> **End of Part 2.3 — Section A (authority + scheduler).**
> Part 2.3 — Section B covers: `gates/`, `provider/`, `prompt/`, `witness_index.rs`, `policy_manager.rs`, and `breakglass.rs`.

---

#### Gates Subsystem (`src/gates/`)

**Role:** The gates subsystem evaluates whether a task's claims are sufficient given its VCS-derived touched paths, and manages the lifecycle of verifier subprocess runs that produce witness artifacts. It is the enforcement point for INV-07 (claim sufficiency) and INV-03 (witness binding).

**Invariant:** Gates never import `raxis-store` directly. All state access goes through the facades: `authority` (delegation + verifier token issuance), `policy` (claim-requirement lookup), `vcs` (range diff), `witness_index` (witness lookup). Each sub-file uses exactly its declared facade set — see boundary rule in Part 2.1.

---

##### `src/gates/mod.rs` — [NEW]

**Purpose:** Single public entry point for gate evaluation. Called by `handlers/intent.rs` after VCS path derivation (and by any handler that re-evaluates claims, e.g. on witness arrival). Never called by the dispatcher directly.

**What it contains:**

- `pub async fn evaluate_claims(session_id: &SessionId, evaluation_sha: &CommitSha, task_id: &TaskId, touched_paths: &[PathBuf], submitted_claims: &[Claim], ctx: &HandlerContext) -> Result<GateEvalResult, GateError>`
  - `evaluation_sha` = `head_commit_sha` from the intent (same value used in `WitnessRecord`); `task_id` = **`req.task_id`** — the plan-defined task row established at `approve_plan`, not allocated by the intent handler.
  - Step 1: `breakglass::check_active(store)` — if `BreakglassStatus::Active`, log `BreakglassAction` for this evaluation, skip remaining steps (2 through 5), return `GateEvalResult::BreakglassPass { activation_id }`. Downstream intent handling still applies (`consume_budget` / `transition_task` per handler rules); only gate enforcement is bypassed. **`record_capability_use` is not called on the break-glass path** — stale delegations remain `StaleOnNextUse` after a break-glass event; the grace use is not consumed by an emergency bypass.
  - Step 2: `policy_lookup::required_claims(touched_paths, &ctx.policy)?` → `Vec<ClaimType>`. The `?` propagates `Err(GateError::PolicyMisconfigured)` immediately. On `Ok(required)`: if `required` is empty and `default_action` is `Permit`, proceed with no claim requirements. **How `StrictDefault` appears in `required`:** it is a literal `ClaimType::StrictDefault` variant appended for any path that matches no rule; the vector is never empty under default-deny (see `policy_lookup.rs`).
  - **Step 2.5 (auto-derive claims from witness records):** Planner-submitted claims (`submitted_claims` parameter) are **discarded**. The kernel constructs `effective_claims: Vec<SubmittedClaim>` by scanning `witness_records` for each required claim type:
    - For each `ClaimType` in `required` (excluding `StrictDefault`):
      - Call `witness::lookup(evaluation_sha, task_id, claim_type_str, None, store)`.
      - If a `WitnessRecord` with `result_class == Pass` exists: push `SubmittedClaim { claim_type, evidence_ref: Some(witness.blob_sha256) }` into `effective_claims`.
    - **Rationale:** The spec originally assumed the planner would actively populate `submitted_claims` referencing witness blobs. This is architecturally unsound — the planner is untrusted (R-1), it has no mechanism to discover required claim types, and the kernel already has the witness evidence. Auto-derivation removes the planner from the trust chain entirely. The planner cannot fabricate a passing witness (only kernel-spawned verifier subprocesses can write to `witness_records` using single-use tokens). This is strictly more secure than planner-submitted claims.
  - Step 3: `claim::evaluate(session_id, &required_claims, &effective_claims, touched_paths, &ctx.authority, &ctx.policy)?` → `ClaimCheckResult`. **Note: `effective_claims` (kernel-derived) is passed, not `submitted_claims` (planner-supplied).** Full variant mapping:
    - `Sufficient` → proceed to step 4. `delegate_renewal_required = false`.
    - `SufficientStale { stale_capabilities }` → proceed to step 4 with `stale_capabilities` captured. `delegate_renewal_required = true`. `record_capability_use` is **not** called yet — see step 4.
    - `Insufficient { failing_claims }` → return `GateEvalResult::ClaimInsufficient { reason: ClaimInsufficient, failing_claims }` without touching scheduler.
    - `DelegationInsufficient { claim_type }` → return `GateEvalResult::ClaimInsufficient { reason: DelegationInsufficient, claim_type }` without touching scheduler.
    - `ScopeInsufficient { claim_type, uncovered_paths }` → return `GateEvalResult::ClaimInsufficient { reason: ScopeInsufficient, claim_type, uncovered_paths }` without touching scheduler.
  - Step 4: For each `GateType` implied by the required claim set: check `witness::lookup(evaluation_sha, task_id, gate_type, None, &ctx.witness_index)`. A `WitnessRecord` with `result_class == Pass` satisfies that gate.
    - If all gate types satisfied **and** `delegate_renewal_required = true`: call `authority::record_capability_use(session_id, cap, &ctx.authority.store)` for each cap in `stale_capabilities`. **This is the sole call site for `record_capability_use` in the entire kernel.** Then return `GateEvalResult::Pass { delegate_renewal_required: true }`. Consuming the grace use here (terminal pass) ensures it is not consumed on failed evaluations or on the intermediate `PendingWitness` path.
    - If all gate types satisfied and `delegate_renewal_required = false`: return `GateEvalResult::Pass { delegate_renewal_required: false }`.
  - Step 5: For unsatisfied gate types: return `GateEvalResult::PendingWitness { missing_gates }`. **`record_capability_use` is not called here.** The recheck (triggered on witness arrival) calls `evaluate_claims` fresh; if delegation is still `StaleOnNextUse` (not yet renewed), the recheck will again reach step 4 with `SufficientStale` and call `record_capability_use` at that point. If the planner renewed the delegation before witnesses complete, the recheck sees `Active` and `delegate_renewal_required = false`.
  - Gate evaluation is idempotent on the `Sufficient` path. On the `SufficientStale` path, idempotency depends on delegation state: if `record_capability_use` already advanced the row to `RenewalRequired`, a re-call would produce `DelegationInsufficient`; the planner must renew to re-establish idempotency.

---

##### `src/gates/claim.rs` — [NEW]

**Purpose:** Evaluates whether a session's submitted claims are sufficient for the required set, given its delegation status. Composes `authority`, `policy`, and `vcs` facades.

**What it contains:**

- `pub fn evaluate(session_id: &SessionId, required: &[ClaimType], submitted: &[Claim], touched_paths: &[PathBuf], authority: &AuthorityCtx, policy: &PolicyBundle) -> Result<ClaimCheckResult, GateError>`
  - `AuthorityCtx` exposes `pub store: Arc<Store>` (or an equivalent accessor). `claim::evaluate` uses `&authority.store` when calling delegation functions. `record_capability_use` is **not** called by this function — it is called exclusively by `gates/mod.rs` after all claims pass and all gate types are satisfied.
  - **The `submitted` parameter receives kernel-derived claims (from Step 2.5 auto-derivation), not planner-submitted claims.** The planner's `submitted_claims` field on the wire is discarded before this function is called.
  - For each `required` claim type:
    - Step A: `authority::check_capability(session_id, capability_for(claim_type), &authority.store)` — **pure read**. Maps result:
      - `NotGranted`, `Expired`, `RenewalRequired` → record `DelegationInsufficient` for this claim type. **First-failure-wins:** evaluation stops at the first delegation failure; remaining claim types in `required` are not evaluated. This is intentional — a missing delegation is a hard prerequisite failure, not a collectable error.
      - `StaleOnNextUse` → append `capability_for(claim_type)` to local `stale_caps: Vec<CapabilityClass>`. **No write.** Mark `any_stale = true`.
      - `Active` → proceed.
    - Step B: Find a matching `Claim { claim_type, scope, justification_blob }` in `submitted` (the kernel-derived effective claims). If none found → record `Insufficient` for this claim type.
    - Step C: `policy_lookup::check_claim_scope(&claim, touched_paths, policy)` — scope must be a superset of `touched_paths`. Mismatch → record `ScopeInsufficient { claim_type, uncovered_paths }`.
  - After evaluating all required claim types (skipping remainder on first DelegationInsufficient — see step A):
    - Any delegation failure detected → `ClaimCheckResult::DelegationInsufficient { claim_type }` (the first one encountered; evaluation did not continue past it).
    - Any submission failures → `ClaimCheckResult::Insufficient { failing_claims }` (collected across all claim types — the full list is useful for planner diagnostics).
    - Any scope failures → `ClaimCheckResult::ScopeInsufficient { claim_type, uncovered_paths }` (first encountered; scope failures are also hard stops).
    - All pass, `any_stale = true` → `ClaimCheckResult::SufficientStale { stale_capabilities: stale_caps }`.
    - All pass, `any_stale = false` → `ClaimCheckResult::Sufficient`.
  - **Failure precedence:** `DelegationInsufficient` > `ScopeInsufficient` > `Insufficient`. If a delegation failure is present, it is returned regardless of B/C failures on the same or other claim types — the delegation check is the hardest prerequisite.

---

##### `src/gates/witness.rs` — [NEW]

**Purpose:** Read-side witness existence check. Does not write witness records — writes go through `ipc/handlers/witness.rs` → `witness_index::write`. Uses `witness_index` facade only.

**What it contains:**

- `pub fn lookup(evaluation_sha: &CommitSha, task_id: &TaskId, gate_type: GateType, verifier_run_id: Option<&VerifierRunId>, witness_index: &WitnessIndex) -> Result<Option<WitnessRecord>, GateError>`
  - Calls `witness_index::lookup(evaluation_sha, task_id, gate_type, verifier_run_id)`.
  - Returns `None` if no matching record; `Some(WitnessRecord)` if found.
  - Does not interpret `WitnessRecord::result_class`. **The sole interpreter of `result_class` is `gates/mod.rs` step 4**, which checks `result_class == Pass` to decide whether a gate is satisfied. `gates/witness.rs` is intentionally kept dumb: it returns the record as stored and never makes a pass/fail judgment. No other module in the kernel calls `witness_index::lookup` directly; all witness reads go through `gates/witness::lookup`, which means the interpretation contract is enforced at a single call site.

---

##### `src/gates/verifier_runner.rs` — [NEW]

**Purpose:** Issues a verifier run token and forks the verifier subprocess with bounded resources. Does not wait for the subprocess result — witness results arrive asynchronously via `ipc/handlers/witness.rs`.

**What it contains:**

- `pub async fn spawn_verifier(task_id: &TaskId, gate_type: GateType, evaluation_sha: &CommitSha, worktree_root: &Path, authority: &AuthorityCtx, config: &VerifierConfig) -> Result<VerifierRunId, GateError>`
  - `authority` carries an internal `Store` handle; token issuance goes through it so `spawn_verifier` does not need a raw `&Store` argument.
  - Step 1: Check global concurrent verifier count against `config.max_concurrent_verifiers`. If at cap, push `(task_id, gate_type, evaluation_sha)` onto the **pending spawn queue** and return `Err(GateError::VerifierCapExceeded)`. The caller (`ipc/handlers/witness.rs` or `handlers/intent.rs` via `evaluate_claims`) includes this gate in `remaining_gates` in the `WitnessAck` (or in the `IntentResponse::Accepted` path's downstream witness ack flow) rather than treating it as an error. When the queue is drained after a verifier exits, the kernel calls `spawn_verifier` from the drain path; this is the only path where `VerifierCapExceeded` does not surface to a handler.

    **Durability and crash semantics:** the pending spawn queue is **in-memory only** — it is **not** persisted to `kernel.db`. On clean shutdown the queue is empty by definition (no verifiers running, nothing to spawn). On crash, all queued spawns are lost. This is **safe** because every task whose gate progress depended on the lost spawns is reconciled to `BlockedRecoveryPending` by `recovery::reconcile_tasks` (per Part 2.2 step 6 + §4.6 `recovery.rs`); after operator `task resume`, the next planner intent re-runs `evaluate_claims` against the persisted `witness_records` (Table 13) and re-spawns whatever verifiers are still missing. No durable queue is needed because the **persistent state of gate progress** (which witnesses have arrived for which `(task_id, gate_type, evaluation_sha)`) lives in `witness_records`, and the **persistent state of task readiness** (which gates a task still needs) is recomputable from policy + `witness_records` at any time. The queue is purely an admission-control optimisation, not a source of truth. See INV-INIT-08.
  - Step 2: `authority::issue_verifier_token(task_id, gate_type, evaluation_sha, config.verifier_token_ttl)` → `VerifierRunToken`. **Implementation contract:** `issue_verifier_token` is sync and acquires the store mutex via `Store::lock_sync()` → `tokio::sync::Mutex::blocking_lock()`. Because `spawn_verifier` is `async` and is called via `.await` from async handlers (`gates::evaluate_gates`, `handlers::witness::handle`), the call to `issue_verifier_token` MUST be wrapped in `tokio::task::spawn_blocking(...).await` here — calling it directly from async context panics with "Cannot block the current thread from within a runtime", which would crash the kernel on the very first verifier spawn. (Latent P0 surfaced by `kernel/src/gates/verifier_runner.rs::integration::*` and pinned by every test in that module; same root cause as the `lifecycle::approve_plan`-vs-`#[test]` rationale documented in `lifecycle.rs`.)
  - Step 3: Build verifier spawn envelope: `{ verifier_run_token, task_id, gate_type, evaluation_sha, kernel_socket_path: config.kernel_socket_path, worktree_root }`. `worktree_root` is passed explicitly (bound to the session at creation; retrieved from the session row before this call).
  - Step 4: Spawn verifier subprocess via `std::process::Command` with the following preparation, applied in order. **Defence-in-depth note:** every measure below is required because the verifier executes operator-supplied (and ultimately repo-content-influenced) code in the same OS user as the kernel; without this hygiene a verifier could (a) inherit the kernel's UDS listener fds and impersonate planner / gateway / operator connections, (b) inherit the open SQLite fd to `kernel.db` and bypass every store-level invariant, (c) inherit open audit segment fds and forge or truncate audit records, (d) inherit witness store directory fds and tamper with prior witness blobs.
    - **Environment scrubbing**: `Command::env_clear()` first, then `env()` only the `VerifierSpawnEnvelope` fields enumerated in [`kernel-store.md`](kernel-store.md) §2.5.6 (`RAXIS_VERIFIER_TOKEN`, `RAXIS_TASK_ID`, `RAXIS_GATE_TYPE`, `RAXIS_EVALUATION_SHA`, `RAXIS_KERNEL_SOCKET`, `RAXIS_WORKTREE_ROOT`, plus the gate-specific vars listed in that section). No `PATH`, no `HOME`, no `USER`, no `TMPDIR`, no terminal vars, no `RAXIS_DATA_DIR` — the verifier must read everything it needs from the envelope. Verifier scripts that need a `PATH` to find git/cargo/etc. must be invoked with absolute interpreter paths and explicit `PATH=` set inside the script, not inherited.
    - **`stdout`/`stderr` piped** to the kernel for line-buffered structured logging into the verifier-run log directory. `stdin` is set to `Stdio::null()` (no inheritance of the kernel's stdin).
    - **FD_CLOEXEC on every long-lived kernel fd** (set when each fd is created during startup, not at spawn time): every UDS listener (`planner.sock`, `gateway.sock`, `operator.sock`), the SQLite connection's underlying file descriptor (open `kernel.db` with `SQLITE_OPEN_PRIVATECACHE | SQLITE_OPEN_NOMUTEX` and immediately apply `fcntl(F_SETFD, FD_CLOEXEC)` on the connection's fd via `rusqlite::Connection::handle().db_filename().fd()` or equivalent), every audit JSONL segment fd, every witness blob fd opened by `witness_index.rs`, and every gateway-process / verifier-process pipe end on the kernel side. `tokio::net::UnixListener` does not unconditionally set CLOEXEC; the kernel must wrap binding via `socket2::Socket::set_cloexec(true)` before `into_std`-converting to a Tokio listener. **CLOEXEC must be the default for every kernel-side fd; explicit `withhold_cloexec` must be opt-in and reviewed.**
    - **`Command::pre_exec` belt-and-suspenders fd close** (defence in depth against any kernel fd that escaped the CLOEXEC default): in the child, before `exec`, enumerate `/proc/self/fd` (Linux) or use `closefrom(3)` (BSD/macOS via `libc`) to close every fd ≥ 3 that is not `stdin`/`stdout`/`stderr`. The pipes the parent set up for `stdout`/`stderr` are intentionally low-numbered and survive; everything else is closed. This step is the safety net: even if a future contributor adds a new long-lived kernel fd and forgets the CLOEXEC default, this pre_exec sweep still closes it. The `pre_exec` closure runs in the forked child process before `exec`; it must be **async-signal-safe** (no allocations, no Rust panics, no library calls beyond raw syscalls — see `nix::unistd` documentation for the hazard).
    - **Resource limits**, applied in `pre_exec` via `nix::sys::resource::setrlimit`: `RLIMIT_CPU = config.verifier_cpu_secs` (CPU-second budget), `RLIMIT_AS = config.verifier_memory_bytes` (address-space ceiling), `RLIMIT_NOFILE = 64` (caps **subsequent** fd allocation by the verifier; **does not retroactively close inherited fds** — that is what the FD_CLOEXEC + `closefrom` steps above are for; see [`kernel-store.md`](kernel-store.md) §2.5.6 `network_allowed` note for why this single rlimit is not a network isolation primitive). `RLIMIT_FSIZE = config.verifier_max_output_bytes` if the gate produces large output. `RLIMIT_NPROC = 8` to bound the verifier's own forks (compilers, test runners typically need a handful).
    - **Working directory**: `Command::current_dir(worktree_root)` so the verifier sees the bound git worktree as `pwd`. The verifier must not need to `cd` anywhere outside `worktree_root` (gates that need to consult repo metadata read from `worktree_root/.git`).
    - **Wall-clock kill**: a `tokio::time::sleep(config.verifier_max_wall_seconds)` task is registered after spawn; on elapse it issues `nix::sys::signal::kill(child_pid, SIGKILL)` and emits `AuditEventKind::VerifierWallClockKilled { verifier_run_id, killed_at }`. The token row's `expires_at` is independent (token TTL bounds the verifier's authorisation window for `WitnessSubmission`; wall-clock kill bounds the subprocess's compute time).
  - Step 5: Increment the global concurrent verifier counter. Register a completion callback (tokio task watching the child PID) that decrements the counter and drains the pending spawn queue on exit.
  - Step 6: Emit `AuditEventKind::VerifierSpawned { verifier_run_id, task_id, gate_type, evaluation_sha }`.
  - Returns `verifier_run_id` immediately. The kernel does not await subprocess completion; the verifier contacts the kernel via UDS when done.

- `pub struct VerifierConfig { verifier_binary_path: PathBuf, verifier_token_ttl: Duration, verifier_cpu_secs: u64, verifier_memory_bytes: u64, max_concurrent_verifiers: usize }` — `max_concurrent_verifiers` is the global cap (v1 default: 16). Loaded from policy at startup; not operator-mutable at runtime without a policy epoch advance.

**Concurrency note:** Multiple tasks may be `GatesPending` simultaneously, each with multiple outstanding gate types. The global cap prevents unbounded subprocess accumulation regardless of the number of concurrent `GatesPending` tasks. The scheduler's lane budget controls the rate at which new tasks enter `GatesPending` — lane admission acts as the upstream backpressure. A `GatesPending` task does not consume lane execution budget (it is not `Running`) but it does count against the task count ceiling in its lane.

---

##### `src/gates/policy_lookup.rs` — [NEW]

**Purpose:** Maps a set of touched file paths to their required claim types, using the policy artifact's claim-requirement table. Returns structured result types — no string codes, no planner-facing mapping.

**What it contains:**

- `pub fn required_claims(paths: &[PathBuf], policy: &PolicyBundle) -> Result<Vec<ClaimType>, GateError>`
  - Iterates `policy.claim_table.rules` in **declaration order** — the order rules appear in the policy artifact's `[[claim_requirements.rules]]` array. For each path, the first matching rule wins; no specificity sorting is applied at load time or evaluation time. **Operator responsibility:** rules must be listed from most specific to least specific, with the catch-all `**` last. The kernel does not reorder rules on your behalf; a misplaced `**` early in the list will swallow paths that should have matched a more specific rule below it. This is the same contract as `.gitignore` and nginx `location` blocks — declaration order is total; specificity is a documentation convention, not an enforcement mechanism.
  - Returns the deduplicated union of required claim types across all paths. `StrictDefault` is a literal `ClaimType` variant; it appears in the returned `Vec` when a path matches no rule, so the vector is never empty under default-deny.
  - **Error return:** returns `Err(GateError::PolicyMisconfigured)` if `default_action` is not `Permit` and the resulting claim set is empty after deduplication (indicates the policy table has rules with empty claim lists on all matched paths without an explicit `permit: []` marker — an operator configuration error, not a planner error). This is an `Err` result, not `Ok(vec![])`, so callers in `gates/mod.rs` that match on the result will not silently treat misconfiguration as "no claims required."

- `pub fn check_claim_scope(claim: &Claim, paths: &[PathBuf], policy: &PolicyBundle) -> ClaimCheckResult`
  - Verifies that the claim's declared `scope` (a path glob or explicit list) covers all paths in `paths`. Scope must be a superset — a claim scoped to `src/auth/**` does not satisfy a requirement over `src/scheduler/admit.rs`.

---

#### Provider Subsystem (`src/provider/`)

**Role:** The provider subsystem handles all outbound data access on behalf of the planner — domain allowlist enforcement, forwarding to the gateway process, SHA-256 computation, rate limiting, and egress audit. It is the enforcement point for INV-02B (no unapproved egress).

**Invariant:** The provider subsystem never opens a network connection directly. All network I/O is delegated to the gateway subprocess via the gateway IPC channel. The kernel process itself has no network capability in production (enforced by the gateway process design; the kernel binary does not link `hyper`, `reqwest`, or any HTTP stack).

---

##### `src/provider/mod.rs` — [NEW]

Re-exports the provider public API.

```text
pub use allowlist::check as allowlist_check;
pub use fetch::execute_fetch;
pub use rate_limit::check_rate_limit;
```

---

##### `src/provider/allowlist.rs` — [NEW]

**Purpose:** Domain allowlist enforcement. The allowlist is defined in the signed policy artifact; the provider reads it at startup and reloads on epoch advance. No network call is made if the allowlist check fails.

**What it contains:**

- `pub fn check(url: &Url, policy: &PolicyBundle) -> AllowlistResult`
  - Extracts the host from `url`. Checks against `policy.egress_allowlist.domains` (exact match) and `policy.egress_allowlist.patterns` (glob match, anchored).
  - Returns `AllowlistResult::Permitted` or `AllowlistResult::Denied { reason: DenialReason }`.
  - Does not log — logging is the caller's responsibility (`handlers/fetch.rs` logs before returning to the planner, per INV-02B).

- `pub fn reload(policy: &PolicyBundle, allowlist_cache: &mut AllowlistCache)`
  - Called by `policy_manager.rs` on epoch advance. Replaces the in-memory allowlist cache atomically (swap behind `ArcSwap`).

---

##### `src/provider/fetch.rs` — [NEW]

**Purpose:** Orchestrates the full fetch pipeline: allowlist check → gateway forward → SHA-256 → egress audit. Called by `ipc/handlers/fetch.rs`.

**What it contains:**

- `pub async fn execute_fetch(&self, url: Url, session_id: &SessionId) -> Result<FetchResult, ProviderError>`
  - `self` is `&ProviderCtx`. All fields accessed as `self.*` (no `ctx` parameter).
  - Step 1: `allowlist::check(&url, &self.policy)` — if not permitted: emits `AuditEventKind::FetchDenied { deny_reason: FetchDenyReason::DomainNotAllowed, fetch_request_id, url, session_id }`, returns `ProviderError::FetchDenied`. Content is never fetched.
  - Step 2: `rate_limit::check_rate_limit(session_id, &self.store)` — deny if session has exceeded fetch quota. Returns `ProviderError::RateLimitExceeded`.
  - Step 3: `self.gateway_channel.forward_fetch(url)` — gateway performs the HTTP request; returns `GatewayResponse { body, status, request_id }`.
  - Step 4: Compute `blob_sha256 = sha256(response.body)`.
  - Step 5: `audit_egress::write_fetch_audit(url, blob_sha256, session_id, received_at, &self.audit)`. **Audit is written before body is returned to the handler.** If the audit write fails, the fetch is aborted and `ProviderError::AuditWriteFailed` is returned — the planner never receives content that is not in the audit log (INV-02B).
  - Step 6: `rate_limit::record_fetch(session_id, &self.store)`.
  - Returns `FetchResult { body: Bytes, sha256: String, status: u16 }`.

---

##### `src/provider/gateway.rs` — [NEW]

**Purpose:** IPC interface to the gateway subprocess. The gateway is a separate process that holds all network capability. The kernel communicates with it over a dedicated UDS channel, not the planner-facing UDS socket.

**What it contains:**

- `pub async fn forward_fetch(url: Url, channel: &GatewayChannel) -> Result<GatewayResponse, ProviderError>`
  - Serializes `FetchRequest { url, request_id: Uuid::new_v4() }` and sends over the gateway channel.
  - Awaits `GatewayResponse { body: Bytes, status: u16, request_id }`. Validates `request_id` matches (prevents response mixing under concurrent fetches).
  - Times out after `config.gateway_fetch_timeout` (v1 default: 30s).

- `pub struct GatewayChannel` — wraps a `tokio::net::UnixStream` to the gateway process. **Held in `ProviderCtx`, accessible via `HandlerContext::provider.gateway_channel`.** Not a top-level field of `HandlerContext`. Reconnects automatically on disconnection with exponential backoff up to `config.gateway_reconnect_max_attempts`.

---

##### `src/provider/rate_limit.rs` — [NEW]

**Purpose:** Per-session fetch rate limiting. Prevents a misbehaving or compromised planner from using the kernel as an unconstrained proxy.

**What it contains:**

- `pub fn check_rate_limit(session_id: &SessionId, store: &Store) -> Result<(), ProviderError>`
  - Reads the session's `fetch_quota` (max fetches per window, written into the session row at session creation from `policy.egress.max_fetches_per_window` at that moment) and the current `fetch_count` in the active window from the `fetch_rate` table.
  - Returns `ProviderError::RateLimitExceeded` if `fetch_count >= session.fetch_quota`. No policy bundle parameter needed at call time — the quota was stamped into the session row at creation; runtime enforcement is a pure store read.
  - **Path A quota exhaustion semantics:** when `check_rate_limit` returns `ProviderError::RateLimitExceeded` (internal), `fetch.rs` maps to `HandlerError::FetchDenied`, dispatcher maps to `PlannerErrorCode::FETCH_DENIED`. Emits `AuditEventKind::FetchDenied { deny_reason: FetchDenyReason::RateLimitExceeded, fetch_request_id, url, session_id }` — same audit variant as allowlist denial, distinguished by `deny_reason`. The task remains non-terminal (`GatesPending` or `Running`). No `BlockReason` is written; no FSM transition fires. The planner receives `FETCH_DENIED` per request and decides whether to abort, retry when the window resets, or continue with non-fetch work.
  - **`FETCH_DENIED` naming:** `PlannerErrorCode::FETCH_DENIED` intentionally omits the `FAIL_` prefix used by gate and policy outcome codes (`FAIL_POLICY_VIOLATION`, `FAIL_MISSING_WITNESS`, etc.). `FAIL_*` codes signal intent-level failures requiring resubmission; `FETCH_DENIED` signals a per-request recoverable denial — the intent itself is not invalidated, and the planner may retry the fetch in the next window or continue without it. Both deny paths (allowlist and rate-limit) map to the same `FETCH_DENIED` code.
  - **The kernel does not auto-terminate a task due to fetch quota exhaustion in v1.** If a future version adds auto-termination (Path B), it must specify the exact threshold, add a `BlockReason` variant (name to be reconciled with the `BlockReason` enum in Gap 4 — provisional: `FetchQuotaExhausted`), and handle the `InitiativeState` transition — that work is explicitly v2, gated as `cfg(feature = "v2-fetch-quota-termination")`.
  - **Independence from lane budget:** `check_rate_limit` has no access to lane budget state and does not consult `estimated_cost`. Session fetch quota and lane admission cost are tuned independently by the operator. See independence statement in `scheduler/budget.rs`.

- `pub fn record_fetch(session_id: &SessionId, store: &Store) -> Result<(), ProviderError>`
  - Increments the fetch counter for the current window. Window boundary is wall-clock aligned (e.g. 1-minute windows) — calculated as `floor(now / window_size) * window_size`.

---

##### `src/provider/audit_egress.rs` — [NEW]

**Purpose:** Writes the fetch audit record. Separated from `fetch.rs` so the audit write path is testable in isolation and so the "audit before release" invariant has a single implementation point.

**What it contains:**

- `pub fn write_fetch_audit(url: &Url, sha256: &str, session_id: &SessionId, received_at: DateTime, audit: &AuditTools) -> Result<(), ProviderError>`
  - Appends `AuditEventKind::FetchExternalDataAudited { fetch_request_id, url, sha256: response_sha256, received_at, returned_at: now() }`. **Field name alignment:** the variant is `FetchExternalDataAudited` (matching Part 1 `raxis-types/audit.rs` and the INV-02B test assertion); the `EgressFetch` name used in an earlier draft is superseded. All audit grep tooling should use `FetchExternalDataAudited`.
  - If append fails: returns `ProviderError::AuditWriteFailed`. Caller (`fetch.rs`) aborts the fetch response — content is not returned to the planner.

---

#### Prompt Subsystem (`src/prompt/`)

**Role:** The prompt subsystem assembles the static scaffold of the planner's system prompt — the portion derived from kernel-known facts (policy epoch, session identity, delegation summary, initiative context). It does not generate natural language; it produces a structured context block the planner model receives as its system prompt prefix. The planner cannot modify this block; it is assembled by the kernel and signed by the epoch.

**Invariant:** The prompt subsystem reads `authority` (session + delegation), `policy` (current epoch + constraints), and `raxis-store` (initiative context) — it is one of the two subsystems that may read store directly (the other is `witness_index`). It does not call `vcs`, `gates`, `scheduler`, or `provider`.

---

##### `src/prompt/mod.rs` — [NEW]

Re-exports the public prompt API.

```text
pub use assembler::assemble;
pub use epoch_binding::{session_prompt_valid, invalidate_session_prompts, mark_all_prompts_invalid};
```

---

##### `src/prompt/assembler.rs` — [NEW]

**Purpose:** Builds the `AssembledPrompt` for a planner session. Called before each planner inference round.

**What it contains:**

- `pub fn assemble(session_id: &SessionId, ctx: &HandlerContext) -> Result<AssembledPrompt, PromptError>`
  - Step 1: `epoch_binding::session_prompt_valid(session_id, &ctx.authority.store)` — checks the `prompt_epoch_valid` flag in the session row (written to `false` by `policy_manager.rs` on epoch advance). `ctx.authority.store` is the `Arc<Store>` held by `AuthorityCtx` (the session row is an authority concern). If `false`, triggers full reassembly and logs `AuditEventKind::PromptReassembled { reason: EpochAdvance, session_id }`.
  - Step 2: Load `SessionRow` from `authority::get_session` — extracts `role`, `worktree_root` (`Option`; **non-NULL** for planner sessions, which are the only callers of `assemble`), `base_sha`.
  - Step 3: Load `Vec<Delegation>` from `authority::list_delegations` — formats as a human-readable capability summary block.
  - Step 4: Load initiative context from store (`initiative_id`, current FSM state, task list with states).
  - Step 5: Load `PolicyBundle` from `ctx.policy.load()` — extracts current `epoch_id`, `constraint_summary`.
  - Step 6: Assemble `AssembledPrompt { epoch_id, session_id, role_block, capability_block, initiative_block, constraint_block, assembled_at }`. No free-form text generation; fields are templated from typed values.
  - **No prompt cache.** Assembly runs on every inference round. The session row flag in Step 1 is a consistency check ("was an epoch advance missed?"), not a cache; there is no in-memory or store-resident cached prompt object to invalidate.

---

##### `src/prompt/epoch_binding.rs` — [NEW]

**Purpose:** Tracks the current policy epoch and signals when assembled prompts need rebuilding due to an epoch advance.

**What it contains:**

- `pub fn current_epoch(policy: &PolicyBundle) -> PolicyEpoch`
  - Returns `policy.epoch_id`. Thin accessor; epoch is owned by `policy_manager.rs`.

- `pub fn session_prompt_valid(session_id: &SessionId, store: &Store) -> Result<bool, PromptError>`
  - Reads `prompt_epoch_valid` flag from the session row. Returns `true` if the prompt is still current, `false` if invalidated by an epoch advance. Called by `assembler::assemble` to determine whether to log a reassembly event.

- `pub fn invalidate_session_prompts(session_id: &SessionId, store: &Store) -> Result<(), PromptError>`
  - Sets `prompt_epoch_valid = false` for the session row. Called by `policy_manager.rs` on epoch advance for a specific session.

- `pub fn mark_all_prompts_invalid(store: &Store) -> Result<usize, PromptError>`
  - Bulk version — sets `prompt_epoch_valid = false` for all active sessions. Returns count of sessions invalidated. Called by `policy_manager::advance_epoch` step 2. **Callable via `prompt::epoch_binding::mark_all_prompts_invalid`** or via the re-export `prompt::mark_all_prompts_invalid` (both work; policy_manager uses the full path).

---

> **End of Part 2.3 — Section B (gates + provider + prompt).**
> Part 2.3 — Section C covers: `witness_index.rs`, `policy_manager.rs`, and `breakglass.rs`.

---

#### `src/witness_index.rs` — [NEW]

**Role:** The single facade that all kernel code uses to read and write witness records. It is the only module that manages both the witness filesystem blob store (`$RAXIS_DATA_DIR/witness/`) and the `witness_records` SQL table in `kernel.db`. Both `gates/witness.rs` (read path) and `ipc/handlers/witness.rs` (write path) go through this module — never around it.

**Storage model:** Witness blobs live on the **filesystem** under `$RAXIS_DATA_DIR/witness/<blob_sha256>` — one file per unique blob, named by the hex SHA-256 of its contents (content-addressed). The `witness_records` SQL table stores only the index metadata: `(verifier_run_id, evaluation_sha, task_id, gate_type, result_class, blob_sha256, blob_path, recorded_at)`. This two-layer design is intentional: large binary blobs in SQLite WAL degrade write throughput and inflate checkpoint size. Storing blobs on the filesystem gives O(1) retrieval by content address, and keeping the index in SQLite gives transactional metadata updates and indexed lookups by `(evaluation_sha, task_id, gate_type)`.

**Invariant:** `witness_index.rs` is the **sole** module that:
1. Writes files to `$RAXIS_DATA_DIR/witness/`
2. Reads or writes the `witness_records` SQL table

No other kernel module may access either storage layer directly. There are no `witness_blobs` or `witness_rows` SQL tables — the SQL witness surface is exactly `witness_records`.

**Crash-window characterisation:** The filesystem blob write and the `witness_records` SQL insert are **not** unified under a single SQLite transaction — the filesystem is a separate subsystem. Write order is always **filesystem first, then SQL index row.** This means:
- If the SQL insert fails after the filesystem write: blob file exists but no index row → **orphaned blob**. The kernel cannot retrieve it via `lookup` (which requires an index row), so it is harmless to correctness. `startup_check` detects and reports it.
- If the filesystem write fails before the SQL insert: neither step completes, the `write()` call returns `Err`, and the witness is not accepted. The verifier may resubmit (the token is not consumed on write failure).
- The reverse (index row inserted, blob missing) cannot occur under correct write order but is detected defensively by `startup_check`.

**What it contains:**

- `pub fn write(record: WitnessRecord, blob: &[u8], ctx: &WitnessIndexCtx) -> Result<VerifierRunId, WitnessError>`
  - `WitnessIndexCtx` carries `{ store: Arc<Store>, witness_dir: PathBuf }` — the store for SQL index writes and the filesystem directory path for blob writes.
  - Write steps:
    1. Compute `blob_sha256 = sha256(blob)`. Verify it matches `record.blob_sha256`; if not → `WitnessError::BlobHashMismatch`. No writes happen on mismatch.
    2. Write blob bytes to `ctx.witness_dir/<blob_sha256>` (filesystem). If the file already exists (content-addressed idempotency — same SHA-256 = same content), skip the write.
    3. Write index row to `witness_records` in `kernel.db` via `ctx.store` with: `verifier_run_id`, `evaluation_sha`, `task_id`, `gate_type`, `result_class`, `blob_sha256`, `blob_path` (= `<blob_sha256>` relative to `witness_dir`), `recorded_at`.
  - Step 3 (SQL insert) runs after step 2 (filesystem write). If step 3 fails, the blob file exists but no index row — orphaned blob, safe, detected by `startup_check` on next startup.
  - Returns `Ok(verifier_run_id)` on success.

- `pub fn lookup(evaluation_sha: &CommitSha, task_id: &TaskId, gate_type: GateType, verifier_run_id: Option<&VerifierRunId>, store: &Store) -> Result<Option<WitnessRecord>, WitnessError>`
  - Queries `witness_records` for a matching index row. If `verifier_run_id` is `Some`, looks up the specific run. If `None`, returns the most recent row for `(evaluation_sha, task_id, gate_type)` ordered by `recorded_at DESC`.
  - Returns the index metadata only — does **not** return blob bytes. Callers that need the raw blob bytes call `get_blob` separately.

- `pub fn get_blob(blob_sha256: &str, witness_dir: &Path) -> Result<Bytes, WitnessError>`
  - Reads `witness_dir/<blob_sha256>` from the filesystem. Returns `WitnessError::BlobNotFound` if the file does not exist (orphaned index row or host filesystem inconsistency).
  - Used by the CLI `audit inspect` command and any path that requires raw verifier output. Not called during normal gate evaluation — `gates/witness.rs` uses `lookup` only, which returns index metadata without blob bytes.

- `pub fn startup_check(store: &Store, witness_dir: &Path) -> Result<WitnessStartupReport, WitnessError>`
  - **Orphaned blobs** — reads all filenames from `witness_dir/`; for each, checks that a `witness_records` row with matching `blob_sha256` exists. Files with no matching row are orphaned blobs.
  - **Orphaned index rows** — reads all `blob_sha256` values from `witness_records`; for each, checks that the corresponding file exists in `witness_dir/`. Rows with no matching file indicate an unexpected store inconsistency.
  - Returns `WitnessStartupReport { orphaned_blobs: usize, orphaned_index_rows: usize }`. Does not delete or repair orphans automatically — logs counts for operator inspection. Orphan deletion is an explicit operator CLI action.

---

#### `src/policy_manager.rs` — [NEW]

**Role:** Loads, verifies, and advances the signed policy artifact via `load_and_verify` (startup) and `advance_epoch` (in-process epoch flip). Owns the `PolicyBundle` shared reference used by all subsystems. Coordinates the epoch advance sequence — the only operation that touches multiple subsystems simultaneously (authority delegations, prompt epoch cache, allowlist cache). See §A.2 for why `advance_epoch` is not "hot reload" in the rejected sense: it is signed, kernel-mediated, and audit-recorded.

**Invariant:** `policy_manager.rs` is the only module that **writes** to the `policy_epoch_history` store table (Table 19, [`kernel-store.md`](kernel-store.md) §2.5.1). The two writers are this module's `advance_epoch` (Phase 1 step 6) and the genesis bootstrap path (`raxis-cli genesis` → `bootstrap::install_genesis_policy`, which writes the `epoch_id = 1` row with `triggered_by_operator = "genesis"` under the same transaction that finalises the schema). Every other subsystem in the kernel observes the current epoch by reading `ctx.policy.load().epoch_id` from the in-memory `Arc<ArcSwap<PolicyBundle>>` — they do **not** issue `SELECT MAX(epoch_id) FROM policy_epoch_history` in the hot path. The only place the table is **read** is `policy_manager::read_current_epoch` (a thin facade used by `load_and_verify` for replay protection at startup and at `advance_epoch`); this is acceptable because both call sites are cold-path (boot, ceremony) and the read is one indexed `MAX` query.

**What it contains:**

- `pub fn load_and_verify(policy_path: &Path, registry: &KeyRegistry) -> Result<PolicyBundle, PolicyError>`
  - Reads the signed policy artifact from `policy_path`.
  - Verifies the Ed25519 signature against `registry.authority_keypair.public`.
  - Verifies the artifact's `epoch_id` is greater than the last known epoch in the store (prevents replay of an old policy artifact).
  - Returns `PolicyBundle` on success; `PolicyError::SignatureInvalid`, `PolicyError::EpochReplay`, or `PolicyError::MalformedArtifact` on failure.
  - Called at startup (step 3) and by `advance_epoch`.

- `pub fn advance_epoch(policy_path: &Path, sig_path: &Path, triggered_by: &OperatorId, registry: &KeyRegistry, ctx: &KernelContext) -> Result<PolicyEpoch, PolicyError>`
  - **Argument note:** takes `&KernelContext` (not `&mut`). The mutability that previous drafts implied is illusory: `ctx.policy` is `Arc<ArcSwap<PolicyBundle>>` (`ArcSwap::store` takes `&self`); `ctx.allowlist_cache` is similarly `Arc<ArcSwap<AllowlistCache>>` (see `provider::allowlist::reload` below); the SQL writes go through the mutex-protected connection on the `Store`. Nothing in the function requires `&mut KernelContext`, and requiring it would conflict with the `Arc<HandlerContext>` shared across handler tasks.
  - Takes explicit `policy_path` and `sig_path` arguments. The operator (via `raxis-cli epoch advance --policy <path> --sig <path>` — see [`cli-ceremony.md`](cli-ceremony.md) §`epoch advance`) specifies which artifact files to load. **No implicit staged location, no fixed path.** Shell history and audit records both capture the exact artifact paths used. The handler validates that both paths canonicalise (`std::fs::canonicalize`) to a location under `<data_dir>/policy/` before opening either file — paths outside the data-dir are rejected with `PolicyError::PathOutsideDataDir`. This prevents an operator from accidentally pointing at a file the kernel UID can read but should not (e.g. another deployment's policy artifact, a build-server staging dir).
  - `triggered_by: &OperatorId` is the operator identity established by the operator socket's challenge-response handshake ([`peripherals.md`](peripherals.md) operator socket auth). It is stored in the audit record as the *triggerer* — distinct from the *signer* (the authority key that signed the artifact, recorded separately below). These can differ: an operator may rotate an artifact that was signed weeks earlier by an authority key that has since been rotated; both identities matter for forensics.

  **Phase 0 — Verification (no side effects).**

  1. Call `load_and_verify(policy_path, registry)` (which itself reads `policy_path` + `sig_path`, runs `Ed25519Verify(authority_pubkey, policy_bytes, sig_bytes)`, parses the TOML, and checks `raw.meta.epoch > store.read_current_epoch()`). On any failure → return the `PolicyError` immediately; no state changes, no audit event for the failed attempt at this step (a separate `PolicyAdvanceRejected` audit event is appended in the dispatcher's error path — see "Audit on rejection" below). The function does NOT acquire the store mutex in this phase; verification is pure and CPU-bound.
  2. Compute `new_bundle = PolicyBundle::from_verified(raw)`.
  3. Compute `policy_sha256 = sha256(policy_bytes)` and `signed_by_authority = registry.authority_keypair.public.fingerprint()` (8-byte truncated SHA-256 of the public key DER, per [`kernel-store.md`](kernel-store.md) §2.5.4 fingerprint convention) — both values are captured from the verification context and used in the audit record at the very end.

  **Phase 1 — SQL transaction (single mutex acquisition, single `BEGIN IMMEDIATE`).**

  The contract from §2.5.1 INV-STORE-01 ([`kernel-store.md`](kernel-store.md)) applies: acquire the `tokio::sync::Mutex<Connection>` once, open `BEGIN IMMEDIATE`, perform all SQL writes against that one transaction handle, then `COMMIT` (or `ROLLBACK` on any error) before releasing the mutex. The mutex is held for the entire transaction body — every other handler that needs the connection waits in FIFO order. This is acceptable because epoch advance is a rare, operator-initiated ceremony; the temporary stall (typically <50 ms, dominated by the `UPDATE delegations` and `UPDATE sessions` row counts) is acceptable for the strong-consistency guarantee.

  4. `authority::mark_stale_on_epoch_advance(&txn)` — `UPDATE delegations SET status = 'StaleOnNextUse' WHERE status = 'Active'`. Returns affected row count `n_delegations_marked_stale: usize` for the audit record.
  5. `prompt::epoch_binding::mark_all_prompts_invalid(&txn)` — `UPDATE sessions SET prompt_epoch_valid = 0 WHERE prompt_epoch_valid = 1`. Returns affected row count `n_sessions_invalidated: usize` for the audit record.
  6. `INSERT INTO policy_epoch_history (epoch_id, policy_sha256, signed_by_authority, triggered_by_operator, advanced_at) VALUES (?, ?, ?, ?, ?)` — writes the new epoch row to **Table 19** in [`kernel-store.md`](kernel-store.md) §2.5.1. Subsequent `read_current_epoch()` calls (`SELECT COALESCE(MAX(epoch_id), 0) FROM policy_epoch_history`) observe this row, providing replay protection: an operator cannot re-present this same artifact, because the next `load_and_verify` epoch comparison is strictly greater than the persisted MAX(epoch_id). The `UNIQUE(policy_sha256)` constraint provides a second line of defence — even an operator who manually edits the artifact's `meta.epoch` to bump it cannot re-present the same byte content under a different epoch_id without the INSERT failing on the unique constraint (returned as `PolicyError::PolicyArtifactAlreadyInstalled` to surface the misuse).
  7. `audit::append(&txn, AuditEventKind::PolicyEpochAdvanced { old_epoch, new_epoch, policy_sha256, signed_by_authority, triggered_by, advanced_at, n_delegations_marked_stale, n_sessions_invalidated })` — appends to the audit segment file (`fdatasync` before continuing, per the audit two-store ordering contract) and records the audit-pointer row in the same transaction.
  8. `COMMIT`. On any error in steps 4–7 → `ROLLBACK` and return `PolicyError::StoreWriteFailed`. The mutex is released in either case.

  **Phase 2 — In-memory visibility flip (after successful `COMMIT`, mutex no longer held, both ops infallible).**

  Phase 2 runs only if Phase 1 committed. Both swaps are infallible Rust operations on `Arc<ArcSwap<_>>` (no I/O, no allocation that can fail in any practical sense for a `PolicyBundle`-sized payload), so once Phase 1 commits, Phase 2 cannot fail.

  9. `ctx.allowlist_cache.store(Arc::new(AllowlistCache::from(&new_bundle)))` — replaces the in-memory domain allowlist cache. Subsequent `provider::check_url` calls see the new allowlist. Old allowlist `Arc` is dropped when its last reader releases.
  10. `ctx.policy.store(Arc::new(new_bundle))` — replaces the `PolicyBundle` reference. **This is the visibility-flip point.** Subsequent calls to `current_epoch(ctx)`, `evaluate_claims`, `assemble_prompt`, `validate_approval_token`, etc. observe the new epoch. Because `ArcSwap::store` is sequentially consistent (`AcqRel` ordering on the swap), no reader can observe the new epoch in `ctx.policy` while the SQL state still shows the old `policy_epoch` row — Phase 1 commits the SQL row first, then Phase 2 swaps the in-memory bundle. The reverse window (SQL has new epoch, ArcSwap still serves old) does exist for the duration between `COMMIT` and the `ctx.policy.store` call (typically microseconds), but is harmless: any handler that reads `ctx.policy.epoch_id` and then queries the store will see the SQL state as "ahead of" the bundle, never "behind"; the only enforcement decisions made from `ctx.policy` are checks against `policy_epoch == ctx.policy.load().epoch()` (e.g. INV-ESC-02), which, if they pass against the old bundle in this microsecond window, would also have passed an instant earlier — there is no decision the kernel could make incorrectly during this window.

  **Phase 3 — Gateway signal (best-effort, out-of-band).**

  11. `ctx.gateway.send(GatewayMessage::EpochAdvanced { new_epoch_id })` — sends the epoch-advance signal to the provider gateway over its dedicated socket. **Best-effort:** if the gateway is unreachable (process crashed, socket closed, IPC buffer full), the kernel logs `AuditEventKind::GatewaySignalFailed { signal: "EpochAdvanced", new_epoch_id, error }` and continues; it does **not** roll back the epoch advance. The gateway's own failure-closed contract ([`peripherals.md`](peripherals.md) §gateway: returns `PolicyReloadFailed` if the next request finds its on-disk allowlist out of sync with the kernel's current epoch) is the second line of defence for this case. The gateway re-reads `policy.toml` on receipt of `EpochAdvanced`; if the re-read fails it enters its own failure-closed mode independent of this signal's delivery.

  **Returns:** `Ok(new_epoch)` after Phase 2 completes. (Phase 3 success/failure does not affect the return value; gateway is a separate process with its own failure contract.)

  **Audit on rejection.** If Phase 0 verification fails (`PolicyError::SignatureInvalid`, `PolicyError::EpochReplay`, `PolicyError::MalformedArtifact`, `PolicyError::PathOutsideDataDir`), the dispatcher (`handlers/operator.rs`) appends `AuditEventKind::PolicyAdvanceRejected { triggered_by, policy_path, sig_path, error_kind, attempted_at }` so that failed advance attempts are forensically visible — an operator repeatedly trying to advance to a malformed artifact is a signal worth recording. If Phase 1 fails after the transaction opened, the rollback leaves no `PolicyEpochAdvanced` audit row and no `PolicyAdvanceRejected` row either (the dispatcher distinguishes the two cases by inspecting which `PolicyError` variant was returned: Phase 0 errors use the rejection event; Phase 1 errors use `AuditEventKind::PolicyAdvanceFailed { triggered_by, attempted_epoch, error_kind, attempted_at }` written *outside* the rolled-back transaction so the failure is captured even though the SQL state is unchanged).

  **Crash semantics.** Because Phase 1 is a single transaction, the crash window is the same as any other single-transaction kernel write: either the transaction committed (kernel recovers with new epoch fully active, allowlist cache will be repopulated from the on-disk policy artifact at next startup via `bootstrap::load_policy`, which uses `policy_path` from `policy_epoch.policy_sha256` lookup — the on-disk path is the canonical artifact location) or it did not (kernel recovers with old epoch fully active). There is no torn state. If the crash happens between `COMMIT` and Phase 2's `ArcSwap` swaps, recovery rebuilds both caches from the new policy artifact at startup — the in-memory state always derives from SQL state on boot, so this is structurally impossible to leave inconsistent.

- `pub fn current_epoch(ctx: &KernelContext) -> PolicyEpoch`
  - Returns `ctx.policy.load().epoch_id`. Thin accessor.

---

#### `src/breakglass.rs` — [NEW]

**Role:** Emergency operator override mechanism. Break-glass activation suspends normal gate evaluation and allows the operator to perform actions that would ordinarily require claims, witnesses, and policy approval. It is an explicitly dangerous capability and is surrounded by ceremony, logging, and strict TTL enforcement.

**Design principles:**
- Break-glass requires **two-operator acknowledgement** in v1: two distinct operator keypair signatures on the activation record. This prevents a single compromised operator credential from enabling break-glass. **Key storage:** operator public keys are held in a sibling struct `OperatorRegistry { operator_keys: Vec<(OperatorId, PublicKey)> }` loaded from the signed policy artifact (operators are registered in policy, not in the genesis key file). `breakglass::activate` receives `operator_registry: &OperatorRegistry` not `KeyRegistry`. This keeps operator identity separate from kernel key material.
- Every action taken during break-glass is logged with `AuditEventKind::BreakglassAction`. The audit record includes the activation record hash.
- Break-glass has a hard TTL (v1: `config.breakglass_max_duration`, default 4 hours). Auto-expires; manual deactivation before TTL is also supported.

**What it contains:**

- `pub struct BreakglassActivation { activation_id: Uuid, justification: String, activated_by: Vec<OperatorId>, activated_at: DateTime, expires_at: DateTime, signature_1: Signature, signature_2: Signature }`

- `pub fn activate(activation: BreakglassActivation, operator_registry: &OperatorRegistry, store: &Store, audit: &AuditTools) -> Result<(), BreakglassError>`
  - Verifies `signature_1` and `signature_2` against keys in `operator_registry.operator_keys`, identifying each signer by `OperatorId`.
  - Checks that `signature_1` and `signature_2` are from distinct operator identities (same-operator double-signing is rejected).
  - Checks `expires_at <= activated_at + config.breakglass_max_duration` (prevents operator from self-issuing an unbounded TTL).
  - Writes activation record to store.
  - Emits `AuditEventKind::BreakglassActivated { activation_id, activated_by, expires_at, justification }`.

- `pub fn check_active(store: &Store) -> Result<BreakglassStatus, BreakglassError>`
  - Returns `BreakglassStatus::Active { activation_id, expires_at }` if an unexpired activation exists.
  - Returns `BreakglassStatus::Inactive` otherwise.
  - Called by gate evaluation (`gates/mod.rs`) at the start of each `evaluate_claims` call — if active, gate evaluation is bypassed but the bypass is logged with `AuditEventKind::BreakglassAction`.

- `pub fn deactivate(operator_id: &OperatorId, operator_sig: &Signature, activation_id: &Uuid, operator_registry: &OperatorRegistry, store: &Store, audit: &AuditTools) -> Result<(), BreakglassError>`
  - Verifies `operator_sig` (one operator signature is sufficient for deactivation). Marks the activation deactivated.
  - Emits `AuditEventKind::BreakglassDeactivated { activation_id, deactivated_by: operator_id, deactivated_at }`.

- `pub fn log_breakglass_action(activation_id: &Uuid, action_description: &str, session_id: &SessionId, audit: &AuditTools) -> Result<(), BreakglassError>`
  - Appends `AuditEventKind::BreakglassAction { activation_id, session_id, action_description, action_at }`.
  - Called by any handler that detects `BreakglassStatus::Active` before proceeding with a bypassed action.

---

#### `HandlerContext` — Subsystem Wiring Summary

All handler functions receive a `&HandlerContext` which holds `Arc`-wrapped references to each initialized subsystem. This section documents the complete field set — it is the compile-time contract that `main.rs` must satisfy when assembling the context at startup.

```rust
pub struct HandlerContext {
    // Authority engine
    pub authority: Arc<AuthorityCtx>,  // wraps KeyRegistry + Store handle
    // Scheduling
    pub scheduler: Arc<SchedulerCtx>,  // wraps Store handle + PolicyBundle ref
    // Gate evaluation
    pub gates: Arc<GatesCtx>,          // wraps AuthorityCtx + PolicyBundle + WitnessIndex + VcsCtx
    // Provider / egress
    pub provider: Arc<ProviderCtx>,    // wraps AllowlistCache + GatewayChannel + Store + AuditTools
    // Prompt assembly
    pub prompt: Arc<PromptCtx>,        // wraps AuthorityCtx + PolicyBundle + Store
    // VCS (global config; per-session worktree_root resolved from ValidatedSession at request time)
    pub vcs: Arc<VcsCtx>,              // wraps KernelConfig.vcs (binary path, timeout); worktree_root not stored here — resolved per-request from session row via authority::get_session
    // HandlerContext is a global (per-kernel) singleton; it is NOT cloned per connection.
    // Per-session mutable state (worktree_root, base_sha, base_tracking_ref, sequence_number) lives in the session
    // store row, not in HandlerContext. Handlers read session state via authority::get_session.
    // Witness facade
    pub witness_index: Arc<WitnessIndex>, // wraps Store
    // Policy (shared across all subsystems)
    pub policy: Arc<ArcSwap<PolicyBundle>>,
    // Audit tools
    pub audit: Arc<AuditTools>,
    // Kernel config (static after startup)
    pub config: Arc<KernelConfig>,
}
```

**Construction order** (enforced in `main.rs` after step 5 store init):
1. `KeyRegistry::load(policy, store)` — keys first; everything else depends on them.
2. `AuditTools::open(config.audit_dir)` — needed by authority and all emitters.
3. `WitnessIndex::new(store.clone())` — no dependencies.
4. `AuthorityCtx::new(key_registry, store.clone())`.
5. `VcsCtx::new(config.vcs)` — per-session worktree_root is set when session is created, not here.
6. `PolicyBundle` loaded by `policy_manager::load_and_verify` — wrapped in `ArcSwap`.
7. `GatewayChannel::connect(config.gateway_socket)` — gateway must be running.
8. All `*Ctx` structs assembled; `HandlerContext` constructed and moved into `Arc`.

---

---

> **End of Part 2.3.**
> Part 2.3 completes the internal kernel specification. The next sections (Part 3+) cover the planner, gateway, verifier crate internals, CLI tooling, test suite design, and the genesis key ceremony.

---

## Part 2.4 — Gap 4: Initiative FSM

**What this gap specifies.** The full lifecycle of an initiative and its constituent tasks: how an initiative moves from `Draft` to `Executing` to terminal; how individual tasks transition through the scheduler and gate pipeline; how the DAG controls task ordering; and what rules determine when an initiative is complete, blocked, failed, or aborted. This is the behavioral contract that `raxis-kernel/src/initiatives/` and `raxis-store/src/initiatives.rs` must implement.

**Relationship to other gaps.**
- Gap 2 (Policy Artifact) defines the signed plan artifact and the lane/claim configuration that feeds initiative creation.
- Gap 3 (Escalation FSM) runs orthogonally — escalations are attached to tasks, not initiatives; initiative state does not change when an escalation is `Pending`.
- `raxis-types/src/initiative.rs` (Part 2.1) defines the raw enum types; this gap defines the transitions, invariants, and evaluation logic that govern those types.

---

### 4.1 — The Initiative / Task Containment Model

An **initiative** is the operator-scoped unit of work. It has a signed plan artifact, a DAG of tasks, terminal criteria, and a lifecycle state. The kernel creates an initiative when the operator or orchestrator submits a signed plan.

A **task** is the planner-executable unit. Each task has a scope (intent kinds it may submit), a lane assignment, dependency edges in the initiative DAG, and its own FSM. The planner interacts with tasks, not directly with initiatives — it submits `IntentRequest` packets that are admitted under a specific task.

**Containment rules:**
- One initiative contains one or more tasks.
- Each task belongs to exactly one initiative.
- A task cannot be moved between initiatives.
- The initiative FSM is driven by the aggregate of its task states — it is derived, not directly settable by the planner.
- The planner cannot create tasks directly; tasks are defined in the signed plan artifact and instantiated by the kernel on initiative admission.

---

### 4.2 — Initiative FSM

#### State inventory

| State | Terminal? | Description |
|---|---|---|
| `Draft` | No | Plan artifact submitted but not yet operator-approved. Tasks not yet instantiated. |
| `ApprovedPlan` | No | Operator has approved the plan artifact. Kernel has instantiated all task rows and DAG edges. Execution not yet started. |
| `Executing` | No | At least one task is in a non-terminal state. The initiative is active. |
| `Blocked` | No | `next_ready_tasks` returns nothing AND no task is `Running`. Every non-terminal task is `GatesPending`, `BlockedRecoveryPending`, or `Admitted` with predecessors not yet `Completed`. `GatesPending`-only deadlock auto-unblocks when witnesses arrive; `BlockedRecoveryPending` requires operator intervention. |
| `Completed` | Yes | Terminal criteria met: all tasks in the completion set are `Completed`. |
| `Failed` | Yes | Terminal criteria evaluated; initiative failed: at least one required task reached `Failed` and no recovery path remains. |
| `Aborted` | Yes | Operator-requested termination, or kernel-detected unrecoverable infrastructure failure across all lanes. |

**`Blocked` is not terminal.** The initiative returns to `Executing` when either `next_ready_tasks` returns a task or a task transitions to `Running` (e.g., operator resumes a `BlockedRecoveryPending` task). Escalation state is orthogonal: a `Running` task with an open escalation is in-flight and keeps the initiative in `Executing` — escalation alone does not produce `Blocked`. `Blocked` requires both `next_ready_tasks` to be empty *and* no `Running` tasks.

#### Transition table

| From | To | Trigger | Actor |
|---|---|---|---|
| *(none)* | `Draft` | Operator/orchestrator submits signed plan artifact | Operator (CLI) |
| `Draft` | `ApprovedPlan` | Operator runs `raxis-cli plan approve <initiative_id>` | Operator (CLI) |
| `Draft` | `Aborted` | Operator runs `raxis-cli plan reject <initiative_id>` | Operator (CLI) |
| `ApprovedPlan` | `Executing` | Kernel admits first task intent from planner | Kernel (on first `IntentRequest`) |
| `Executing` | `Completed` | Terminal criteria evaluation returns `Complete`, via `evaluate_terminal_criteria` after task state updates (typically on task terminal transition) | Kernel (`evaluate_terminal_criteria`) |
| `Executing` | `Failed` | Terminal criteria evaluation returns `Failed`, via `evaluate_terminal_criteria` after task state updates (typically on task terminal transition) | Kernel (`evaluate_terminal_criteria`) |
| `Executing` | `Blocked` | All non-terminal tasks are in non-runnable states (detected by `evaluate_terminal_criteria` called after each task state write) | Kernel (`evaluate_terminal_criteria`) |
| `Blocked` | `Executing` | `next_ready_tasks` becomes non-empty or a task transitions to `Running` (detected by `evaluate_terminal_criteria` called after each task state write — e.g., `GatesPending → Admitted` makes `next_ready_tasks` non-empty) | Kernel (`evaluate_terminal_criteria`) |
| `Blocked` | `Aborted` | Operator runs `raxis-cli initiative abort <initiative_id>` while blocked (`AbortInitiative`) | Operator (CLI) |
| `Executing` | `Aborted` | Operator runs `raxis-cli initiative abort <initiative_id>` (`AbortInitiative`) | Operator (CLI) |

**Invalid transitions (kernel must reject):**
- Any transition from `Completed`, `Failed`, or `Aborted` — initiative rows are immutable once terminal.
- `Draft → Executing` without passing through `ApprovedPlan` — the plan must be operator-approved before tasks can run.
- `ApprovedPlan → Completed` / `Failed` / `Blocked` — cannot reach a terminal or blocked state without ever executing.

#### Terminal criteria and initiative state evaluation

After every `transition_task` call — terminal and non-terminal — the kernel runs `lifecycle::evaluate_terminal_criteria(initiative_id, store)`. This is the single hook that keeps initiative state (`Executing`, `Blocked`, `Completed`, `Failed`) consistent with task state. Running it after non-terminal writes (e.g., `Admitted → GatesPending`) is required to detect the `Executing → Blocked` transition in cases where no terminal task exists yet. This function:

1. Loads the initiative's `terminal_criteria` from the signed plan artifact. Criteria are defined at plan time and cannot be changed after approval.
2. Evaluates the criteria against the current task state snapshot.
3. Returns one of: `StillExecuting` | `Complete` | `InitiativeFailed` | `AllTerminalNoSuccess`.

**Built-in criteria shapes** (defined in the plan artifact schema; the v1 enum is exhaustively the three rows below):

| Variant | Rule | Failure detection |
|---|---|---|
| `AllTasksSucceeded` | All tasks reached `TaskState::Completed`. **Default** if `terminal_criteria` is omitted from the plan. Serialised as the JSON string `"AllTasksSucceeded"` (see [`kernel-store.md`](kernel-store.md) §2.5.1 Table 2 `terminal_criteria_json`). | If any task transitions to `Failed` or `Aborted`, the criterion is unsatisfiable — returns `InitiativeFailed { cause_task_id }` (the first such task) at the next `evaluate_terminal_criteria` call after that task transition. Because `evaluate_terminal_criteria` runs synchronously inside `transition_task`'s transaction (§4.6, INV-INIT-04), the initiative reaches `Failed` in the same atomic write that observed the task failure — `RetryTask` (§4.6 `retry_task`) is too late to recover under this variant; see "Operator decision on partial failure" below. |
| `AllTasksTerminal` | All tasks reached any terminal state (`Completed` / `Failed` / `Aborted`). Use when the operator wants the initiative to wait for full closure regardless of per-task outcome. Serialised as `"AllTasksTerminal"`. | Cannot be detected early — the criterion is only resolved once every task is terminal. At that point: returns `Complete` if ≥1 task is `Completed`, else `AllTerminalNoSuccess` (which the caller maps to `InitiativeFailed`). |
| `MinSuccessCount(u32)` | At least `n` tasks reached `TaskState::Completed`. Use for parallel-attempt initiatives — `MinSuccessCount(1)` is the "any one wins" idiom. Serialised as the JSON object `{"MinSuccessCount": <n>}`. | Compute `successes_remaining_possible = non_terminal_count + completed_count`; if this drops below `n`, the criterion is unsatisfiable — returns `InitiativeFailed`. |

**Variants explicitly deferred from v1** (recorded so the absence is not mistaken for an omission, and so any out-of-spec variant a plan tries to use is rejected at parse time with a clear error):

- **`RequiredSetSucceeded(Vec<TaskId>)`** — named subset must succeed while other tasks may fail. Deferred because the v1 plan schema has no per-task `optional` flag; every task in a v1 plan is treated as required, which makes `AllTasksSucceeded` strictly equivalent. Will be reconsidered when per-task optionality is introduced.
- **`AnyCompleted`** — degenerate case of `MinSuccessCount(1)`. Removed as a separate variant to keep the surface minimal; use `MinSuccessCount(1)` instead.
- **`AllTasksCompleted`** — eliminated as a name because it is ambiguous: `Completed` is the success state in the task FSM (see §4.3 state inventory), but "completed" in plain English can mean any terminal state. The two intents are now spelled `AllTasksSucceeded` (success-only) and `AllTasksTerminal` (any terminal).
- **`CustomScript(path)`** — defers to a future v2 sandbox model. The v1 kernel has no script execution surface and will reject any plan whose `terminal_criteria_json` deserialises to `CustomScript`.

**General failure-detection invariant.** Failure detection only fires when the criterion can no longer be satisfied by any reachable task state — it is not speculative. The per-variant rules in the third column above are exhaustive; `evaluate_terminal_criteria` does not consult any other heuristic.

**`AllTerminalNoSuccess`** is the `InitiativeEval` return value reserved for the `AllTasksTerminal` pathological case (every task terminal, none `Completed`). It is internal to the evaluator: callers see `InitiativeFailed` after the mapping in `evaluate_terminal_criteria` (see `lifecycle.rs` below). It is not a `TerminalCriteria` variant.

---

### 4.3 — Task FSM

#### State inventory

| State | Terminal? | Runnable? | Description |
|---|---|---|---|
| `Admitted` | No | Derived | Task instantiated; `next_ready_tasks` returns it only when all DAG predecessors are `Completed`. All tasks start `Admitted` at `approve_plan` time — there is no separate "holding" state for predecessor-blocked tasks. Schedulable = `next_ready_tasks` eligible, not a stored flag. |
| `GatesPending` | No | No | Kernel received first gated `IntentRequest` for this task; verifiers spawned; witnesses not yet all received. Not returned by `next_ready_tasks`. |
| `Running` | No | N/A — in-flight | Task picked up from `next_ready_tasks`; planner has taken at least one work turn. `Running` tasks are **not** returned by `next_ready_tasks` — the planner continues via its session-bound in-flight task context, not via a new scheduler pick-up. |
| `Completed` | Yes | — | Planner reported task success; kernel accepted. |
| `Failed` | Yes | — | Planner reported task failure (work attempted, did not meet criteria). |
| `Aborted` | Yes | — | Kernel-recorded infrastructure failure. Always carries `BlockReason`. |
| `Cancelled` | Yes | — | Bulk-cancelled task (initiative-level failure or `abort_initiative`); not used for per-task operator abort — that is **`Aborted` + `OperatorAbort`** via `task abort`. |
| `BlockedRecoveryPending` | No | No | Task interrupted mid-execution; awaiting operator recovery decision. Not returned by `next_ready_tasks`. |

**Schedulable** = returned by `scheduler::next_ready_tasks`. `next_ready_tasks` returns only `Admitted` tasks (not `GatesPending`, not `Running`). Schedulability for `Admitted` tasks is derived at query time — `next_ready_tasks` returns an `Admitted` task only if all its DAG predecessors are `Completed`. Schedulability is not a stored field on the task row.

**`Admitted` at plan approval vs at predecessor completion:** All tasks are instantiated as `Admitted` at `approve_plan` time. Tasks with unmet predecessors are `Admitted` in the store but not returned by `next_ready_tasks` until their predecessors complete. `release_successors` does not change the task row state — it records the predecessor completion in the DAG edge table so that the next `next_ready_tasks` query includes the successor. There is no separate stored state for "waiting for predecessors."

**`Admitted` vs `GatesPending`:** `Admitted` is the non-terminal stored state for tasks that are not `GatesPending`, `Running`, `BlockedRecoveryPending`, or terminal. Schedulability — whether the task is returned by `next_ready_tasks` — is a derived property computed at query time from the DAG edge table, not a flag stored on the task row. `GatesPending` means verifiers are outstanding and the task is not returned by `next_ready_tasks` regardless of predecessor state. When all gates clear, the task transitions `GatesPending → Admitted` and becomes eligible for `next_ready_tasks` (subject to its predecessors being `Completed`).

**`Running` and the planner continue-work path:** A `Running` task is already in-flight. The planner continues submitting `IntentRequest` packets carrying the same `task_id` (the task binding field — see `src/intent.rs` in `raxis-types`) — it does not go through `next_ready_tasks` again. The kernel validates the `task_id` against the session's in-flight task context. A `Running` task with an open escalation is still in-flight; the escalation is orthogonal. As long as any task is `Running`, the initiative remains `Executing`.

#### Transition table

| From | To | Trigger | Actor |
|---|---|---|---|
| *(none)* | `Admitted` | Initiative moves to `ApprovedPlan`; kernel instantiates task; DAG predecessors already `Completed` (or task has no predecessors) | Kernel (plan approval) |
| `Admitted` | `GatesPending` | Kernel evaluates intent; claim table requires gates; verifiers spawned | Kernel (on `IntentRequest`) |
| `GatesPending` | `Admitted` | All required witnesses submitted and accepted; gate recheck passes | Kernel (on `WitnessSubmission`) |
| `GatesPending` | `Aborted` | Verifier token TTL expired without witness; kernel timeout sweep | Kernel (sweep) |
| `Admitted` | `Running` | Planner submits `IntentRequest`; no gates required or gates already cleared | Kernel (on `IntentRequest`) |
| `Running` | `Completed` | Planner submits `IntentRequest { intent_kind: CompleteTask }`; kernel accepts | Kernel (on intent) |
| `Running` | `Failed` | Planner submits `IntentRequest { intent_kind: ReportFailure, justification }` | Kernel (on intent) |
| `Running` | `Aborted` | Infrastructure failure: witness timeout, delegation expired, provider timeout, or unrecoverable kernel error | Kernel |
| `Running` | `BlockedRecoveryPending` | Kernel crashed and restarted; task was `Running` at crash time; `recovery::reconcile` marks it pending. **V2.5:** if the previous exit was a supervisor-classified auto-restartable code (deadlock / panic / signal-crash), `recovery::reconcile_after_supervisor_restart` immediately re-emits the `BlockedRecoveryPending → Admitted` edge (with `actor = "kernel"`) for every freshly-swept task EXCEPT operator-quarantined initiatives and pre-existing-block rows, per `INV-SUPERVISOR-AUTO-RESUME-ON-CLEAN-RESTART-01`. | Kernel (recovery sweep) |
| `BlockedRecoveryPending` | `Running` | Operator runs `raxis-cli task resume <task_id>` after reviewing audit log | Operator (CLI) |
| `BlockedRecoveryPending` | `Aborted` | Operator runs `raxis-cli task abort <task_id>` (declines recovery; `BlockReason::OperatorAbort`) | Operator (CLI) |
| `Admitted` | `Aborted` | Operator runs `raxis-cli task abort <task_id>` before planner picks up the task (`OperatorAbort`) | Operator (CLI) |
| `Running` | `Aborted` | Operator runs `raxis-cli task abort <task_id>` (`OperatorAbort`) | Operator (CLI) |
| `Failed` | `Admitted` | Operator runs `raxis-cli task retry <task_id>` (`RetryTask` IPC); precondition `task.state == Failed` AND `initiative.state ∈ {Executing, Blocked}`. Resets `session_id`, `evaluation_sha`, `base_sha`, `submitted_claims_json`, `admission_reserved_units`, `actual_cost` so the next planner pickup runs fresh. Goes through `transition_task`, so `evaluate_terminal_criteria` fires; may transition initiative `Blocked → Executing` if this re-enables `next_ready_tasks`. See `lifecycle::retry_task` (§4.6) for the full handler spec and the criterion-dependent applicability table in §4.5 "Operator decision on partial failure". | Operator (CLI) |

**Successor schedulability rule:** When a task transitions to `Completed`, the kernel calls `store::dag::release_successors(task_id)`. This records the predecessor-satisfied marker on the DAG edge record and causes the next `next_ready_tasks` query to include successors whose full predecessor set is now `Completed`. The successor's stored task row state remains `Admitted` throughout — `release_successors` does not issue a state transition. The planner cannot force a successor to be returned by `next_ready_tasks` before its predecessors complete.

**`Cancelled` vs `Aborted`:** **`Aborted`** with **`BlockReason::OperatorAbort`** covers operator-initiated **task abort** via CLI (`AbortTask` IPC). **`Cancelled`** is used for **bulk** termination when an initiative fails criteria or the operator aborts the whole initiative (`abort_initiative`), where tasks are mass-cancelled without per-task `transition_task` (see `lifecycle::abort_initiative`). Kernel-initiated infrastructure failures also produce **`Aborted`** with other `BlockReason` variants. The planner cannot directly abort — it uses `ReportFailure` → `Failed`, not operator abort.

---

### 4.4 — `BlockReason` Taxonomy

Every `Aborted` task carries exactly one `BlockReason`. The `BlockReason` enum is exhaustive — no variant may be added without also updating `recovery::reconcile_tasks` and the `raxis-cli status` CLI display.

**`BlockReason` variants used with `TaskState::Aborted`:**

| `BlockReason` | Cause | Recovery path |
|---|---|---|
| `WitnessTimeout` | Verifier token TTL elapsed without `WitnessSubmission` | Investigate verifier environment; fix; submit new intent with new SHA |
| `WitnessFailure` | Verifier submitted `WitnessResult::Fail` | Fix the underlying failure (build broken, tests failing); new commit; new intent |
| `DelegationInsufficient` | Claim evaluation found no valid (non-stale) delegation | Renew delegation; re-submit intent |
| `DelegationExpired` | Delegation TTL elapsed; grace period exhausted | Request delegation renewal from operator |
| `ProviderTimeout` | Gateway response timeout on every retry within the task | Operator investigates provider; task may be resubmitted with new intent |
| `BudgetExhausted` | Lane cost ceiling hit; no budget for new reservations. Set by the scheduler when `SchedulerError::BudgetExceeded` is returned at admission; `transition_task` is called by the scheduler with `actor: Kernel` and `reason: BudgetExhausted`. | Submit `BudgetException` escalation or reduce task scope |
| `PolicyEpochMismatch` | Policy epoch advanced mid-task; session's epoch pin is now stale | Re-authenticate session under new epoch; re-submit intent |
| `OperatorAbort` | Operator explicitly aborted the task via CLI | No recovery; issue is resolved manually |
| `UnrecoverableKernelError` | Kernel recorded an internal error it cannot recover from | Operator reviews audit log; manual decision required |

**`BlockReason` variant used with `TaskState::BlockedRecoveryPending` only — not with `Aborted`:**

| `BlockReason` | Cause | Resolution |
|---|---|---|
| `RecoveryPendingOperatorAction` | Kernel restart interrupted a `Running` task; set by `initiatives::recovery::reconcile_tasks` (called as part of the top-level `recovery::reconcile` in Part 2.2) at startup. Never set during normal execution. | Operator runs `raxis-cli task resume` or `raxis-cli task abort`; the task is not terminal until the operator decides. |

---

### 4.5 — DAG Execution Mechanics

#### Plan artifact DAG definition

The signed plan artifact includes a task list and a dependency graph. The kernel instantiates this at `ApprovedPlan` time.

```toml
[[tasks]]
task_id       = "task-auth-tests"
lane_id       = "default"
description   = "Fix and verify the auth token reuse regression"
intent_kinds  = ["SingleCommit", "CompleteTask"]
depends_on    = []           # no predecessors; eligible immediately

[[tasks]]
task_id       = "task-integration"
lane_id       = "default"
description   = "Run integration suite after auth fix"
intent_kinds  = ["CompleteTask"]
depends_on    = ["task-auth-tests"]   # blocked until task-auth-tests is Completed
```

**Validation at `ApprovedPlan` time:**
1. All `depends_on` references must resolve to task IDs within the same initiative.
2. The DAG must be acyclic — the kernel runs a topological sort and rejects the plan if a cycle exists.
3. All `lane_id` values must be present in the signed policy artifact.
4. All `intent_kinds` must be valid `IntentKind` variants.

If validation fails, the plan is rejected and the initiative stays in `Draft`.

#### Successor release on task completion

```text
task "task-auth-tests" → Completed

store::dag::release_successors("task-auth-tests"):
  load successors: ["task-integration"]
  for each successor:
    load predecessor list from DAG edge table
    all predecessors Completed? → yes
    mark DAG edge record as predecessor-satisfied
    emit AuditEventKind::SuccessorSchedulable { task_id: "task-integration", unblocked_by: "task-auth-tests" }
    # task row state: still Admitted — no state transition

next_ready_tasks() now returns "task-integration"  ← successor eligible at next query
planner picks it up on next scheduling cycle
```

**No implicit parallelism.** Tasks with no shared dependencies can be picked up by the planner in any order, and multiple sessions can work on them concurrently (v1-compatible). The DAG only enforces ordering constraints — it does not schedule tasks onto specific sessions.

#### DAG failure propagation

When a task reaches `Failed` or `Aborted`, its successors are not automatically cancelled. The kernel evaluates terminal criteria after each terminal transition. If the criteria evaluation returns `InitiativeFailed` (e.g., a required task failed), the initiative moves to `Failed` and all non-terminal tasks transition to `Cancelled`. If the criteria evaluation returns `StillExecuting` (e.g., the failed task was optional), the initiative continues and successors of the failed task remain `Admitted` in the store but will never be returned by `next_ready_tasks` (their predecessor is not `Completed` and never will be — they are permanently non-schedulable unless the initiative is aborted and re-submitted).

**Operator decision on partial failure:** Whether `RetryTask` can usefully recover a failed task depends on the initiative's `terminal_criteria` (§4.2). The applicability table below is the normative reference for operator runbooks:

| Criterion | First task `Failed` ⇒ | Operator `RetryTask` outcome | Recommended path |
|---|---|---|---|
| `AllTasksSucceeded` (default) | `evaluate_terminal_criteria` synchronously moves the initiative to `Failed`; all non-terminal tasks → `Cancelled` (`lifecycle::abort_initiative`-style mass-cancel inside the same transaction). | `retry_task` rejects with `TaskError::InitiativeTerminal` because the initiative is already terminal. | Re-submit a new initiative (with the same or corrected plan) via `raxis-cli plan submit` + `plan approve`. |
| `MinSuccessCount(n)` | If `successes_remaining_possible = non_terminal_count + completed_count` ≥ `n`, criterion stays `StillExecuting` and initiative remains `Executing` (or transitions to `Blocked` if no other task is runnable). Otherwise → `InitiativeFailed`. | If `Executing`/`Blocked`: `retry_task` resets the failed task to `Admitted`, the post-write `evaluate_terminal_criteria` may transition `Blocked → Executing`. If already `Failed`: rejected with `TaskError::InitiativeTerminal`. | Use `raxis-cli task retry <task_id>` while initiative is non-terminal; choose this criterion deliberately when retries are anticipated. |
| `AllTasksTerminal` | No early failure detection — criterion only resolves once every task is terminal. Initiative stays `Executing` (or `Blocked`) while any task is non-terminal. | `retry_task` always succeeds for individual `Failed` tasks while the initiative is non-terminal — there is no synchronous failure verdict to race against. | Use `raxis-cli task retry <task_id>` freely; useful when the operator wants per-task closure regardless of outcome. |

In all three rows, `retry_task` is the **only** v1 operator-initiated transition from a terminal task state. **`Aborted` and `Cancelled` tasks are not retryable in v1**: `Aborted` is a kernel-recorded infrastructure failure or operator abort (terminal by design — re-attempt requires re-submitting the initiative); `Cancelled` is a bulk-termination side-effect of initiative failure or `abort_initiative` (per-task retry is meaningless because the initiative itself is terminal). `BlockedRecoveryPending` uses `ResumeTask`, not `RetryTask` (different precondition — the task was interrupted, not failed).

Plan amendment (`raxis-cli plan amend`) is a v2 feature that would let an operator add or modify tasks within an in-flight initiative; in v1 the only operator-initiated lifecycle operations on individual tasks are `RetryTask`, `ResumeTask`, and `AbortTask`, and on initiatives are `ApprovePlan`, `RejectPlan`, and `AbortInitiative`.

#### Task lifetime bounds (no v1 task-level deadline)

**Normative statement.** v1 has **no automatic task-level deadline.** Neither `tasks` ([`kernel-store.md`](kernel-store.md) §2.5.1 Table 5) nor `initiatives` (Table 2) carries a `deadline_at` column; no kernel sweep periodically scans `tasks` for `now() > deadline_at` and forces a transition; no `BlockReason::DeadlineExpired` variant exists in the §4.4 taxonomy. A task that the planner stops touching can in principle remain in `Running` (or `GatesPending`, or `Admitted`) indefinitely. This is **deliberate** — task-level deadlines are a v2 feature (see "v2 plan" below) — and pinned by **INV-INIT-09**.

**Why the spec is honest about this gap.** Two sites in [`kernel-store.md`](kernel-store.md) (§2.5.6 `CompleteTask` path-policy-violation flow at L1802, and §2.5.7 `CompleteTask` path-failure decision matrix at L1905) explicitly call out that `CompleteTask` rejection paths can leave a task in `Running` indefinitely if the planner never satisfies the path check. That disclosure is correct: under v1's rules, the path-rejection planner loop is bounded only by (a) budget exhaustion, (b) operator action, or (c) the planner itself submitting `ReportFailure`. There is no kernel timer.

**What practically bounds task lifetime in v1 (in order of likelihood for a runaway task):**

| Lifetime bound | Mechanism | Time horizon |
|---|---|---|
| **Lane budget exhaustion (`max_cost_per_epoch`)** | Each `IntentRequest` that consumes budget calls `consume_budget` against `lane_budget_reservations` (§4.6 `handlers/intent.rs` "Budget check and reservation"). Once a task's lane has no remaining admission units, the next intent that would charge fresh budget returns `IntentResponse::Rejected { reason: FAIL_BUDGET_EXCEEDED }`. The planner can either submit `ReportFailure` (→ `Failed`) per [`peripherals.md`](peripherals.md) §"Budget awareness" guidance, or open a `BudgetException` escalation. If the operator denies the escalation and the planner cannot proceed, the task de-facto stalls until either a new `epoch advance` resets `max_cost_per_epoch` or the operator aborts. **In typical use this fires within hours**, not weeks. | Hours (typical lane budgets are sized for one operator-shift of work) |
| **Lane concurrency cap (`max_concurrent_tasks`)** | Indirect bound: a runaway task occupies a `max_concurrent_tasks` slot on its lane and prevents other tasks from being admitted, creating operator pressure to abort it. Not a hard timer, but a strong forcing function in deployments with active multi-task workflows. | Same-shift (operator notices when other work blocks) |
| **Verifier subprocess rlimits (`RLIMIT_CPU`, `RLIMIT_AS`)** | Each verifier subprocess spawned by `gates::verifier_runner::spawn_verifier` (§Iteration 9 FD-hygiene contract) has hard CPU and memory rlimits set via `Command::pre_exec`. A verifier that hangs or runs away will be killed by the kernel (signal SIGXCPU on `RLIMIT_CPU` exceedance). The owning task transitions `GatesPending → Aborted` with `BlockReason::WitnessTimeout` once the verifier token's `expires_at` passes (the in-process wall-clock watchdog also fires; see `verifier_runner` step 4). This bounds *one verifier-spawn cycle*, not the whole task. | `verifier_cpu_secs` (default in `VerifierConfig`, typically tens of seconds to minutes per spawn) |
| **Provider gateway timeout** | Inference and fetch calls go through the provider gateway with per-call timeouts. Repeated timeouts produce `BlockReason::ProviderTimeout` on the task (per §4.4 taxonomy). This is per-call, not per-task. | Per-call seconds; aggregated effect bounded by `max_cost_per_epoch` |
| **Operator levers** | (a) `raxis-cli task abort <task_id>` → `Running → Aborted` with `BlockReason::OperatorAbort` (§4.3 transition table, INV-INIT-05 vicinity); (b) `raxis-cli initiative abort <initiative_id>` → mass-cancels every non-terminal task in the initiative; (c) `raxis-cli session revoke <session_id>` → invalidates the session token, so the planner's next `IntentRequest` returns `UNAUTHORIZED` and the task can no longer make progress (the task row stays in its current state until the operator also aborts it, but no further state changes can be planner-driven). | Manual; bounded by operator vigilance |
| **Policy epoch advance side-effect** | An `advance_epoch` (§`policy_manager.rs`, Iteration 12) does **not** by itself terminate any task. It marks delegations stale-on-next-use and invalidates session prompts, which forces the planner to renew before the next gated action. A planner that cannot renew (e.g. the operator declines to re-grant the delegation under the new policy) will be unable to submit further gated intents; the task de-facto stalls until operator abort. | Indirect; depends on operator delegation decisions |
| **Planner-initiated termination (`IntentKind::ReportFailure`)** | Cooperative: the planner itself submits `ReportFailure` with a justification. Transitions `Running → Failed` (§4.3). Used when the planner determines the task cannot succeed (e.g. budget exhaustion per [`peripherals.md`](peripherals.md) §"Budget awareness"). | Planner-discretion; depends on planner self-monitoring |

**Operator runbook implications.** Operators monitor task wall-clock health through the v1 read-only CLI surface ([`cli-readonly.md`](cli-readonly.md)): `raxis status` and `raxis top` for at-a-glance dashboards, `raxis queue --blocked-only` to see what is stuck, `raxis explain <task_id>` to get a structured "why isn't this moving" answer, and `raxis log -f --kind TaskStateChanged` (or a richer filter) for live state transitions. There is no kernel-emitted audit event that fires automatically when a task exceeds a wall-clock threshold; the operator can either (a) subscribe to the policy-configured Shell notification channel (`raxis inbox -f`, which receives every `TaskStateChanged` if the operator routes that event in `policy.toml [[notifications.routes]]` per [`cli-readonly.md`](cli-readonly.md) §5.6), or (b) run a periodic cron that calls `raxis status --json` and alerts on long-running tasks. The kernel emits `AuditEventKind::TaskStateChanged` on every transition, so a downstream log pipeline can also compute "time since last transition" for each task and alert on outliers.

**v2 plan.** Task-level deadlines are a planned v2 addition. The minimal v2 surface (subject to revision in the v2 spec) would consist of: (a) optional `deadline_at INTEGER` columns on `tasks` and `initiatives` (NULL = no deadline), populated from new optional fields in the signed plan artifact (`task.deadline_seconds_from_admission`, `initiative.deadline_seconds_from_approval`); (b) a new `BlockReason::DeadlineExpired` variant in §4.4; (c) a periodic kernel sweep (similar in shape to the escalation-timeout sweep in [`kernel-store.md`](kernel-store.md) §2.5.1 Table 8, "best-effort kernel background task; may fire slightly after the deadline") that scans non-terminal tasks/initiatives for `now() > deadline_at` and calls `transition_task(..., reason: Some(DeadlineExpired), actor: Kernel, ...)`; (d) a new audit event `TaskDeadlineExpired { task_id, deadline_at, observed_at, transitioned_to: Aborted }`; (e) the existing `RetryTask` operator path remains the recovery mechanism for `Failed` tasks but is **not** authorised for `Aborted-due-to-DeadlineExpired` (consistent with INV-INIT-07 — `Aborted` is non-retryable; the operator must re-submit a new initiative if the deadline was wrong). The v1 implementation deliberately omits this entire surface to keep the v1 minimal-correct deliverable focused; the absence is documented via INV-INIT-09 and the practical-bounds table above so that v1 deployments can budget operator vigilance accordingly rather than discover the gap during an incident.

**What the planner sees.** The `IntentResponse::Rejected { reason }` enum ([`peripherals.md`](peripherals.md) §3.1) does **not** include any `FAIL_TASK_DEADLINE_EXPIRED` variant in v1. If the planner wishes to self-impose a deadline (e.g. for cooperative cancellation), the planner-side runtime can track its own wall-clock and submit `IntentKind::ReportFailure` with a justification citing self-imposed timeout. The kernel records the `ReportFailure` and transitions the task `Running → Failed` (per §4.3); no kernel-side timer is involved. This is the cooperative equivalent of a v1 deadline.

---

### 4.6 — `src/initiatives/` Handler Specifications

#### `src/initiatives/mod.rs` — [NEW]

Re-exports the public initiative API: `create`, `approve_plan`, `reject_plan`, `abort`, `evaluate_terminal_criteria`, `retry_task`.

---

#### `src/initiatives/lifecycle.rs` — [NEW]

**What it contains:**

- `pub fn create_initiative(plan: SignedPlanArtifact, store: &Store, audit: &AuditTools) -> Result<InitiativeId, InitiativeError>`
  - Verifies the plan artifact's Ed25519 signature using the **operator's** public key, looked up from `policy.operator_entry(plan.sig.signed_by).public_key` (the four-key custody model in [`kernel-store.md`](kernel-store.md) §2.5.4 reserves `registry.authority_keypair` for `ApprovalProof` and never uses it to verify plans). If `plan.sig.signed_by` does not resolve to a known operator entry in the current policy bundle, returns `InitiativeError::UnknownSigner` (mapping to `FAIL_UNKNOWN_SIGNER` per [`kernel-store.md`](kernel-store.md) §2.5.3 L1180). The exact verification call is `Ed25519Verify(operator_pubkey, plan.sig.plan_sha256, plan.sig.signature)` — operating on the SHA-256 digest, not the raw bytes, per the byte-exact signing domain in §2.5.3.
  - Validates the DAG (acyclic, all references resolve, all lane IDs in policy).
  - Inserts the initiative row with `status: Draft`.
  - Emits `AuditEventKind::InitiativeCreated { initiative_id, plan_hash, signed_by, signed_at }`. `plan_hash` is hex SHA-256 of `plan_bytes` (matches `initiatives.plan_artifact_sha256`); `signed_by` is the operator pubkey fingerprint copied verbatim from `plan.sig.signed_by` (SHA-256[:16] of the operator's Ed25519 public key, hex-encoded — see [`kernel-store.md`](kernel-store.md) §2.5.3 `plan.sig` format); `signed_at` is the Unix-seconds timestamp from `plan.sig.signed_at`. Carrying `signed_by` and `signed_at` in the audit payload preserves the signer trail in the audit log even if the on-disk `plan.sig` file is later removed, rotated, or rewritten by a follow-on ceremony — the `signed_plan_artifacts` row stores only the raw signature bytes (`plan_sig`) and not the signer fingerprint or signing timestamp.
  - Does not instantiate task rows — that happens at `approve_plan`.

- `pub fn approve_plan(initiative_id: InitiativeId, approved_by: OperatorId, store: &Store, audit: &AuditTools) -> Result<(), InitiativeError>`
  - Verifies initiative is in `Draft` state; else `InitiativeError::InvalidTransition`.
  - Instantiates all task rows from the plan's `[[tasks]]` stanzas as `TaskState::Admitted`. DAG edges are written to `store::dag`. Tasks with predecessors are `Admitted` in the store but will not be returned by `next_ready_tasks` until their predecessors complete — there is no separate stored holding state.
  - Transitions initiative to `ApprovedPlan`.
  - Emits `AuditEventKind::PlanApproved { initiative_id, approved_by, task_count }`.

- `pub fn reject_plan(initiative_id: InitiativeId, rejected_by: OperatorId, store: &Store, audit: &AuditTools) -> Result<(), InitiativeError>`
  - Verifies initiative is in `Draft` state; else `InitiativeError::InvalidTransition`.
  - Discards the draft (no task rows exist yet). Transitions initiative to `Aborted`.
  - Emits `AuditEventKind::PlanRejected { initiative_id, rejected_by }` (or equivalent audit variant consistent with `raxis-types`).

- `pub fn evaluate_terminal_criteria(initiative_id: InitiativeId, store: &Store, audit: &AuditTools) -> Result<InitiativeEval, InitiativeError>`
  - **Called after every task state write** — both terminal and non-terminal. The function is cheap when nothing changes: it loads the task state snapshot, checks terminal criteria, then checks blocked/unblocked condition in a single pass.
  - Loads task state snapshot and the initiative's `terminal_criteria`.
  - Evaluates criteria; returns `StillExecuting | Complete | InitiativeFailed | AllTerminalNoSuccess`.
  - If `Complete` → transitions initiative to `Completed`; emits `InitiativeCompleted`.
  - If `InitiativeFailed` or `AllTerminalNoSuccess` → transitions initiative to `Failed`; cancels all non-terminal tasks; emits `InitiativeFailed { cause_task_id }`.
  - If `StillExecuting` → checks whether `next_ready_tasks` is non-empty OR any task is `Running`:
    - If **yes** and initiative is `Blocked` → transitions initiative to `Executing`; emits `AuditEventKind::InitiativeResumed { initiative_id, at }`.
    - If **no** and initiative is `Executing` → transitions initiative to `Blocked`; emits `AuditEventKind::InitiativeBlocked { initiative_id, at }`.
    - If neither condition changes — no initiative state write.
  - **This is how the single-task gated case is handled:** `Admitted → GatesPending` is a non-terminal write; `evaluate_terminal_criteria` is called; `next_ready_tasks` returns nothing and no task is `Running` → initiative transitions `Executing → Blocked`. When the witness arrives and `GatesPending → Admitted`, `evaluate_terminal_criteria` is called again; `next_ready_tasks` now returns the task → initiative transitions `Blocked → Executing`.
  - If all non-terminal tasks are `GatesPending`, the initiative enters `Blocked` but auto-unblocks when witnesses arrive — no operator action needed. Only `BlockedRecoveryPending` tasks require operator action to resume.
  - **Atomicity and mutex scope (normative).** All reads (task state snapshot, `next_ready_tasks` query) and all writes (initiative state row, audit event inserts, any cascading task-row writes for `InitiativeFailed`/`Cancelled` paths) happen inside the **same SQL transaction** opened by the calling `transition_task` — `evaluate_terminal_criteria` does **not** open its own `BEGIN` or `COMMIT`. That outer transaction in turn runs **inside one continuous acquisition of the `Arc<Mutex<Connection>>` held by `raxis-store::Store`** (the single-connection model in [`kernel-store.md`](kernel-store.md) §2.5.1 isolation model). The mutex must be held from the start of `transition_task`'s `BEGIN IMMEDIATE` through its `COMMIT`, including the entire body of `evaluate_terminal_criteria`. Releasing the mutex between the task-row write and the criterion evaluation would expose an intermediate state in which the task row has its new value but the initiative state has not yet been recomputed — another tokio task could observe the inconsistency. **Implementation rule for `transition_task`:** acquire the mutex once, open `BEGIN IMMEDIATE`, perform the row write + audit insert + `evaluate_terminal_criteria` call (which itself performs reads and conditional writes via the same locked connection handle), then `COMMIT` (or `ROLLBACK` on any error from any sub-step), then release the mutex. **Implementation rule for `evaluate_terminal_criteria`:** the function takes `store: &Store` but expects the caller to have already acquired the mutex and opened a transaction; it accesses the connection through the existing transaction handle (`rusqlite::Transaction<'_>`) passed in via the `store`-shaped façade, never via a fresh `store.acquire()` or `store.begin()` call. Calling `evaluate_terminal_criteria` outside an open `transition_task` transaction is a spec violation (and `transition_task` is the only authorised caller per INV-INIT-04, so the rule is auto-enforced by the call-site invariant). **No deadlock risk** because the kernel uses `tokio::sync::Mutex` (FIFO, async-aware): any other handler waiting for the connection during this critical section is parked, not spinning, and is woken in arrival order when the mutex is released.

- `pub fn abort_initiative(initiative_id: InitiativeId, aborted_by: OperatorId, store: &Store, audit: &AuditTools) -> Result<(), InitiativeError>`
  - Verifies initiative is not already terminal.
  - Bulk-cancels all non-terminal tasks via direct store writes — **not** through `transition_task`. Each cancelled task row emits `AuditEventKind::TaskCancelled { task_id, initiative_id, reason: "initiative aborted", aborted_by }` individually. `transition_task` is intentionally bypassed here because the initiative is being force-terminated: there is no per-task criterion evaluation, and `evaluate_terminal_criteria` is not invoked. The initiative state is written directly to `Aborted` in the same store transaction.
  - Transitions initiative to `Aborted`.
  - Emits `AuditEventKind::InitiativeAborted { initiative_id, aborted_by }`.

- `pub fn retry_task(task_id: TaskId, retried_by: OperatorId, store: &Store, audit: &AuditTools) -> Result<(), TaskError>`
  - **Operator-initiated** transition `Failed → Admitted` for a single task. Dispatched from the `RetryTask { task_id }` operator IPC variant (see [`kernel-store.md`](kernel-store.md) §2.5.5 operator IPC discriminant table); the CLI ergonomics are documented in [`cli-ceremony.md`](cli-ceremony.md) §`task retry`.
  - **Preconditions** (validated in this order; first failing check returns immediately, no writes):
    1. Task row exists for `task_id`; else `TaskError::InvalidTask`.
    2. Operator has `RetryTask ∈ permitted_ops` for the policy entry matching `retried_by` (enforced by the dispatcher before this handler runs; `retry_task` itself trusts the dispatcher's authorisation result and does not re-check `permitted_ops`).
    3. `task.state == TaskState::Failed`; any other state → `TaskError::NotRetryable { current_state }`. The dispatcher maps this to the planner-side error code `FAIL_TASK_NOT_RETRYABLE { current_state }` for the operator CLI display per [`cli-ceremony.md`](cli-ceremony.md) §`task retry`. Specifically rejected: `Aborted` (terminal by infrastructure or operator decision in v1 — abort is non-retryable; re-attempt requires re-submitting the initiative), `Cancelled` (bulk-terminated by initiative-level operation; per-task retry is meaningless because the initiative is itself terminal), `BlockedRecoveryPending` (uses `ResumeTask`, not `RetryTask`), `Completed` (already succeeded), `Admitted` / `GatesPending` / `Running` (not yet failed — nothing to retry).
    4. Initiative containing this task is **not** in a terminal state (i.e., `initiative.state ∈ {ApprovedPlan, Executing, Blocked}`); else `TaskError::InitiativeTerminal`. This catches the common `AllTasksSucceeded`-after-failure case where the initiative was synchronously transitioned to `Failed` by `evaluate_terminal_criteria` inside the same transaction that observed the task failure (see §4.5 "Operator decision on partial failure" for the criterion-dependent retry applicability table).
  - **State reset**, all in a single store transaction:
    - Read `prior_failure_reason: Option<BlockReason>` from the current task row before any write (always `None` for `Failed` tasks in v1, since `Failed` is only ever set by planner `ReportFailure` which carries no `BlockReason` — the field is captured for the audit event so the variant shape stays stable if a future iteration extends `RetryTask` to `Aborted`).
    - `UPDATE tasks SET session_id = NULL, evaluation_sha = NULL, base_sha = NULL, submitted_claims_json = NULL, admission_reserved_units = NULL, actual_cost = 0` for `task_id`. `session_id = NULL` allows any planner session to re-pick this task; the SHA fields and `submitted_claims_json` reset so the next pickup starts from a fresh planner-supplied range; `admission_reserved_units = NULL` and `actual_cost = 0` reset the budget bookkeeping (the prior `lane_budget_reservations` row was deleted at the prior terminal transition by `release_budget`, so there is no row collision when the next intent's `consume_budget` runs).
    - Call `transition_task(task_id, TaskState::Admitted, None, TransitionActor::Operator(retried_by), current_policy_epoch, store, audit)` to perform the actual `Failed → Admitted` write. Going through `transition_task` (not a direct `UPDATE state = 'Admitted'`) ensures the FSM transition table in §4.3 is enforced (the new `Failed → Admitted` row is the operator-only authorised path) and the standard post-write `evaluate_terminal_criteria` hook fires — for an initiative under `MinSuccessCount` or `AllTasksTerminal` this may transition `Blocked → Executing` if the retried task makes `next_ready_tasks` non-empty; under `AllTasksSucceeded` the initiative was already terminal and precondition 4 above would have rejected the call.
  - **Audit:** `transition_task` emits the standard `TaskTransitioned { task_id, from: Failed, to: Admitted, actor: Operator(retried_by), ... }`. `retry_task` additionally emits `AuditEventKind::TaskRetried { task_id, initiative_id, retried_by, prior_failure_reason: Option<BlockReason>, at }` so audit queries can isolate operator-driven retries from ordinary scheduler-driven `Admitted` transitions without parsing `from_state` history. Both audit writes are in the same store transaction as the row update.
  - **Budget side-effect:** `retry_task` does **not** touch `lane_budget_reservations`. The next `IntentRequest` from the planner picks up at the "no row exists yet for `(lane_id, task_id)`" branch in `handlers/intent.rs` (§3.4) and runs `check_budget` + `consume_budget` afresh. Each retry therefore charges the lane its full `compute_admission_cost` again — there is no de-duplication of budget across retries; this is intentional, since each retry genuinely re-does the work. A future `policy.tasks.max_retries` field could bound this at policy level (deferred to v2).
  - **DAG side-effect:** none. Predecessors of the retried task were already `Completed` (else the planner could not have picked it up to fail it). After the reset the task is immediately re-eligible via `next_ready_tasks` (subject to the criterion-dependent initiative state check in precondition 4 above). Successors of the retried task remain `Admitted` and only become eligible when the retry itself reaches `Completed` and triggers `release_successors`.
  - **Idempotency:** `retry_task` is **not** idempotent across calls — a second invocation while the task is in `Admitted` (i.e., the planner has not yet re-picked it up) returns `TaskError::NotRetryable { current_state: Admitted }`. The operator should observe via `raxis-cli status <task_id>` that the first `RetryTask` succeeded before issuing another. Within a single connection, IPC-level idempotency keys (per [`kernel-store.md`](kernel-store.md) §2.5.1 Table 16 nonce cache) collapse exact-duplicate `RetryTask` envelopes to one effective call.

---

#### `src/initiatives/task_transitions.rs` — [NEW]

**What it contains:**

- `pub fn transition_task(task_id: TaskId, new_state: TaskState, reason: Option<BlockReason>, actor: TransitionActor, policy_epoch: u64, store: &Store, audit: &AuditTools) -> Result<(), TaskError>`
  - **Mutex acquisition (first action).** Acquires the single `Arc<tokio::sync::Mutex<Connection>>` held by `raxis-store::Store` (the single-connection model in [`kernel-store.md`](kernel-store.md) §2.5.1 isolation model). The mutex is held continuously from this acquisition through `COMMIT` / `ROLLBACK` below — every sub-step (validation read, row write, `release_successors` call, audit insert, `evaluate_terminal_criteria` call with its conditional initiative-state write and `Cancelled` cascade) executes against the locked connection. **No sub-step releases the mutex; no sub-step opens a nested transaction.**
  - **Transaction open.** Issues `BEGIN IMMEDIATE` on the locked connection (acquires SQLite's reserved-lock immediately so any concurrent read-only path that may be added later cannot overtake the write). All subsequent statements within this function and within the `evaluate_terminal_criteria` it invokes execute against this single transaction handle.
  - Loads current task state; validates transition is permitted (enforces the transition table in §4.3). On invalid transition → `TaskError::InvalidTransition` (caller maps as appropriate); the function `ROLLBACK`s and releases the mutex before returning.
  - Writes new state, `reason`, `actor`, `policy_epoch`, and `transitioned_at` to the task row.
  - If `new_state` is terminal and `reason` is `None` but terminal state requires one (e.g., `Aborted`) → `TaskError::MissingBlockReason` (`ROLLBACK` + release).
  - If `new_state` is `Completed` → calls `store::dag::release_successors(task_id)` (still inside the same transaction; `release_successors` writes DAG edge marker rows, not task state).
  - **Unconditionally** calls `lifecycle::evaluate_terminal_criteria(initiative_id, ...)` after the state write — both terminal and non-terminal. This is the single call-site that keeps initiative state consistent with task state (INV-INIT-04). `evaluate_terminal_criteria` runs against the same open transaction handle (see its "Atomicity and mutex scope" note above) and may itself issue further writes (initiative state row, `Cancelled` cascades, audit events) — all of those are part of this same transaction.
  - **Audit insert.** Emits `AuditEventKind::TaskTransitioned { task_id, initiative_id, from_state, new_state, reason, actor, policy_epoch }` via `audit::append` (which writes into the same SQL transaction for the audit-pointer tables AND appends to the JSONL audit segment file — JSONL append is outside SQL but is `fdatasync`'d before `COMMIT` per the audit subsystem's two-store ordering contract; see Part 2.2 audit semantics). Any audit-side error → `ROLLBACK` + release.
  - **Transaction commit.** `COMMIT`. Then release the mutex. The `Result<(), TaskError>` returned to the caller reflects the outcome of the `COMMIT`: `Ok(())` means every state change above is durable on disk (per `PRAGMA synchronous = FULL`); any `Err` means nothing was committed.

- `pub enum TransitionActor { Kernel, Planner(SessionId), Operator(OperatorId), RecoverySweep }`

  **Trust invariant:** `Planner(session_id)` may only trigger `Running → Completed` and `Running → Failed` transitions. All other transitions must have actor `Kernel`, `Operator`, or `RecoverySweep`. If a planner-sourced request triggers any other transition, `transition_task` returns `TaskError::Unauthorized`.

  **Alignment with `handlers/intent.rs`:** `handlers/intent.rs` calls `transition_task` with `actor: TransitionActor::Kernel` for the `Admitted → Running` and `Admitted → GatesPending` edges — these are kernel-initiated transitions in response to a planner `IntentRequest`, not planner-initiated transitions. The planner submits an intent; the kernel decides the state change.

---

#### `src/initiatives/recovery.rs` — [NEW]

> **V2.1 supersession notice — recovery becomes advisory.**
>
> The recovery orchestrator described below is the V1 / V2.0 mechanism.
> Under the V1 ordering, `recovery::reconcile` is **mandatory** for chain
> integrity: any (SQLite COMMIT, JSONL fsync) crash window leaves a chain
> gap that only `reconcile` can repair. This is the strict-R-7 violation
> documented in `v2/audit-paired-writes.md §1`.
>
> Under V2.1+ the orchestrator is renamed `reconcile_advisory` and its
> role is downgraded:
>
> - **Chain integrity does NOT depend on it running.** The paired-write
>   protocol (`StateChangePending` → `<existing kind>` →
>   `StateChangeRolledBack`) makes every state-mutating crash window
>   resolvable by an offline forensic verifier from a frozen SQLite
>   snapshot alone — see `v2/audit-paired-writes.md §6` and
>   `INV-AUDIT-PAIRED-06`.
> - **What it does instead.** When recovery runs, it calls the offline
>   verifier (`crates/audit/src/verifier.rs::verify`) over the on-disk
>   chain + the live SQLite snapshot, and synthesises the missing
>   `confirmed` (for committed orphans) and `StateChangeRolledBack {
>   reason: CrashInferred }` (for inferred-rolled-back orphans) so the
>   chain becomes self-resolving for future verifications. Recovery
>   never modifies SQLite state on behalf of an orphan — the SQLite
>   row IS the ground truth, the chain is what gets repaired.
> - **Critical-finding handling.** If the verifier returns any
>   `Finding::is_critical` — chain break, dangling confirmed,
>   dangling rollback, digest mismatch — recovery refuses to proceed
>   and the kernel refuses to start until an operator runs
>   `raxis verify-chain --acknowledge-critical` (signed) to override.
>   Critical findings are operator-attention events, not auto-fixable.
> - **Task FSM recovery is unchanged.** `reconcile_tasks` (the
>   non-terminal-task → `BlockedRecoveryPending` sweep) and
>   `expire_orphan_verifier_tokens` retain their V1 behaviour and
>   are still called by `reconcile_advisory`. Their internal SQL
>   transitions become paired-class events under V2.1 (each emits a
>   `StateChangePending` before its own `BEGIN IMMEDIATE` and a
>   confirmed `TaskTransitioned` after `COMMIT`), so the recovery sweep
>   itself is structurally R-7-compliant.
>
> See `v2/audit-paired-writes.md §6` for the full advisory-recovery
> contract, including the V2.1 verifier algorithm and the boot-time
> integration with `raxis-kernel`.

**What it contains (V1 / V2.0 mechanism, retained as advisory in V2.1):**

- `pub fn reconcile_tasks(store: &Store, audit: &AuditTools) -> Result<ReconcileReport, RecoveryError>`
  - Called by `recovery::reconcile` (Part 2.2 top-level recovery orchestrator) as its task-specific step — not invoked independently. `recovery::reconcile` orchestrates audit chain verification, witness orphan reconciliation, and then delegates task recovery to this function. There is one normative recovery entry point (`recovery::reconcile` in `main.rs`); `reconcile_tasks` is not called from `main.rs` directly. **In V2.1+ the entry point is `recovery::reconcile_advisory` and its return on success is best-effort (advisory-recovery contract); the boot path proceeds whether or not `reconcile_advisory` repaired any orphans.**
  - Queries **all non-terminal tasks**: `state NOT IN (Completed, Failed, Aborted, Cancelled)`. This includes `Admitted`, `GatesPending`, `Running`, and (idempotently) any task already in `BlockedRecoveryPending` from a prior unfinished sweep. The broad sweep is normatively defined in Part 2.2 step 6 `reconcile_tasks` description and is **mandatory**: omitting `GatesPending` would leave tasks pointing at dead verifier subprocesses with no recovery path; omitting `Admitted` would leave tasks holding `lane_budget_reservations` from a prior `consume_budget` whose owning planner session is gone. **`Cancelled` is terminal** and must be in the exclusion set so bulk-cancelled tasks are never swept into `BlockedRecoveryPending`.
  - For each interrupted task: calls `transition_task(task_id, BlockedRecoveryPending, RecoveryPendingOperatorAction, RecoverySweep, ...)`. `transition_task` emits `AuditEventKind::TaskTransitioned` and calls `evaluate_terminal_criteria`, which detects the loss of `Running` / `Admitted` / `GatesPending` tasks and transitions affected initiatives from `Executing` to `Blocked`.
  - After each `transition_task` call, `reconcile_tasks` also emits `AuditEventKind::TaskNeedsRecovery { task_id, initiative_id, prior_state, interrupted_at }` as a separate, operator-visible event. `prior_state` is the pre-recovery `TaskState` (`Admitted` / `GatesPending` / `Running` / `BlockedRecoveryPending`) and is captured before the `transition_task` call so the operator can choose an appropriate recovery action — e.g., a task that was in `GatesPending` may need a fresh planner intent to re-trigger gate evaluation, while a task that was in `Running` may be safe to resume directly. `TaskNeedsRecovery` is not part of `TaskTransitioned`; it is a dedicated recovery-surface event emitted by `reconcile_tasks` itself.
  - **After all task transitions complete**, calls `expire_orphan_verifier_tokens(store, audit)` (see below) in the same recovery transaction so zombie tokens are invalidated atomically with the recovery sweep.
  - Returns `ReconcileReport { recovered_task_count, affected_initiative_ids, orphaned_token_count }`.
  - Does NOT auto-resume any task. Operator must run `raxis-cli task resume` or `raxis-cli task abort`.

- `pub fn expire_orphan_verifier_tokens(store: &Store, audit: &AuditTools) -> Result<usize, RecoveryError>`
  - **Purpose**: invalidates `verifier_run_tokens` rows whose verifier subprocess died with the kernel and whose owning task has now been swept to `BlockedRecoveryPending`. Without this pass, those rows would remain valid (`consumed = 0`, `expires_at` in the future) for the remainder of the original `expires_at` TTL, creating a defence-in-depth gap: if a stray subprocess somehow survived the kernel crash and submitted a witness within the TTL window, the kernel would accept it.
  - **Selection**: `SELECT verifier_run_id, task_id, gate_type, evaluation_sha FROM verifier_run_tokens WHERE consumed = 0 AND expires_at > unix_now() AND task_id IN (SELECT task_id FROM tasks WHERE state = 'BlockedRecoveryPending')`.
  - **Action**: for each selected row, `UPDATE verifier_run_tokens SET expires_at = unix_now() WHERE verifier_run_id = ?`. Setting `expires_at` to "now" makes the existing `validate_verifier_token` check 2 (`now() < expires_at`) reject any subsequent presentation as `AuthorityError::TokenExpired` — no new validation logic, no schema change. The row is preserved (not deleted) so the audit trail and FK from `witness_records.verifier_run_id` remain intact for forensic queries.
  - **Audit**: emits one `AuditEventKind::VerifierTokenOrphaned { verifier_run_id, task_id, gate_type, evaluation_sha, orphaned_at }` per row so operators can correlate dead subprocesses with the recovery sweep. The token's pre-recovery `expires_at` is captured in the audit payload as `original_expires_at` for forensic completeness.
  - Returns the count of expired rows. Returns `Ok(0)` if no orphans were found (clean shutdown, or all `BlockedRecoveryPending` tasks already had their tokens consumed pre-crash).
  - **Idempotency**: re-running the function is a no-op once tokens are expired (the `expires_at > unix_now()` selector excludes them). Safe to re-invoke if recovery itself crashes mid-sweep and re-runs.

- `pub fn resume_task(task_id: TaskId, operator_id: OperatorId, store: &Store, audit: &AuditTools) -> Result<(), RecoveryError>`
  - Verifies task is in `BlockedRecoveryPending`.
  - Calls `transition_task(task_id, Running, None, Operator(operator_id), ...)`. `transition_task` unconditionally calls `evaluate_terminal_criteria`, which detects the new `Running` task and transitions any `Blocked` initiative back to `Executing` (emitting `InitiativeResumed` if the initiative state changes).
  - `resume_task` does not directly manipulate initiative state — all initiative state updates flow through `evaluate_terminal_criteria` inside `transition_task`. This is the single call-site guarantee.
  - **Gate-progress preservation:** `resume_task` always lands the task in `Running`, regardless of whether its `prior_state` (per the `TaskNeedsRecovery` audit event) was `Running`, `GatesPending`, or `Admitted`. Pre-crash gate progress is preserved through `witness_records` (Table 13) — when the planner submits its first post-resume `IntentRequest`, `handlers/intent.rs` re-runs `evaluate_claims` which consults `witness_records` for each required gate at the current `evaluation_sha`. Witnesses that arrived before the crash satisfy their respective gates without re-execution; gates with no matching witness re-spawn fresh verifiers via `gates::verifier_runner::spawn_verifier`. Verifier tokens issued before the crash were invalidated by `expire_orphan_verifier_tokens` during the recovery sweep, so any stray pre-crash subprocess that somehow re-presents its token is rejected with `AuthorityError::TokenExpired`. This means: **for tasks whose `prior_state == GatesPending`, the operator's resume + planner's first intent together restore gate evaluation to a consistent state without any explicit re-queue or re-spawn step in `resume_task` itself.** See INV-INIT-08 for the full invariant statement.

---

### 4.7 — Integration Test Matrix (Gap 4)

**Happy path — linear DAG:**
- Plan with two tasks: A (no predecessors), B (depends on A).
- Initiative created → `Draft`.
- Operator approves → `ApprovedPlan`; both tasks instantiated as `Admitted`. Task B is `Admitted` but not yet schedulable (`next_ready_tasks` excludes it — predecessor A not yet `Completed`).
- Planner picks up task A (returned by `next_ready_tasks`) → `Running`.
- Planner completes task A → `Completed`; `release_successors` fires; B becomes schedulable — `next_ready_tasks` now returns B.
- Planner picks up task B → `Running` → `Completed`.
- `evaluate_terminal_criteria` returns `Complete` (all tasks completed).
- Initiative → `Completed`. Verify: no non-terminal tasks remain; initiative row is `Completed`.

**Happy path — parallel tasks, partial dependency:**
- Plan: tasks A, B (independent), C (depends on A and B).
- Both A and B schedulable immediately (`next_ready_tasks` returns both — no predecessors). Planner completes A; B still `Running`.
- C is `Admitted` but not schedulable (`next_ready_tasks` excludes it — B not yet `Completed`).
- B completes → `release_successors` for B; C's predecessors now all `Completed` → C becomes schedulable via `next_ready_tasks`.
- C completes → initiative `Completed`.

**Task failure in required set:**
- Plan: tasks A and B. Criterion: `AllTasksSucceeded` (default).
- A completes. B fails (`WitnessFailure`).
- `evaluate_terminal_criteria`: required task B is `Failed`; returns `InitiativeFailed { cause_task_id: B }`.
- Initiative → `Failed`; task A remains `Completed`; no state change needed.
- Verify: initiative is `Failed`; audit log contains `InitiativeFailed`.

**Initiative blocked — progress deadlock (all tasks non-runnable):**
- Scenario: all tasks are `GatesPending` and all witnesses time out → all tasks → `Aborted { WitnessTimeout }` → `evaluate_terminal_criteria` → `AllTerminalNoSuccess` → initiative → `Failed`. No `Blocked` state entered because all tasks became terminal.
- Scenario: one task in `Running`; planner submits escalation (task stays `Running`, escalation is orthogonal); if the task genuinely cannot proceed without the escalated capability, the planner reports `ReportFailure` → task → `Failed` → `evaluate_terminal_criteria` → `InitiativeFailed`. The escalation `Pending` or `TimedOut` state does not directly drive the initiative to `Blocked` — only the task state does.
- Scenario producing `Blocked`: all non-terminal tasks are `GatesPending` (witnesses not yet arrived) and no other runnable tasks exist. Initiative enters `Blocked` but will auto-unblock when witnesses arrive — no operator action needed for this case.

**Recovery sweep at startup — `Running` task:**
- Kernel crashes while task X is `Running`.
- Kernel restarts; `reconcile_tasks` runs before IPC listener starts.
- Task X transitions to `BlockedRecoveryPending`.
- `expire_orphan_verifier_tokens` runs — finds no unconsumed tokens for X (X was `Running`, not `GatesPending` — no verifiers were active). Returns 0.
- Initiative transitions to `Blocked` (no runnable tasks remain).
- Operator runs `raxis-cli task resume X` → task → `Running`; initiative → `Executing`.
- Verify: audit log contains `TaskNeedsRecovery { prior_state: Running }`, then `TaskTransitioned { from: BlockedRecoveryPending, to: Running, actor: Operator }`; initiative state transitions are consistent; no `VerifierTokenOrphaned` events.

**Recovery sweep at startup — `GatesPending` task with active and queued verifiers:**
- Kernel crashes while task Y is `GatesPending`. At crash time: 2 verifier subprocesses are running for gate types G1 and G2 (with `verifier_run_tokens` rows; tokens unconsumed; `expires_at` 30 minutes in the future); 1 spawn is queued in the in-memory pending queue for gate type G3 (no `verifier_run_tokens` row yet — token is only issued at the moment of actual spawn). One witness for an earlier gate type G0 is already in `witness_records` for Y's current `evaluation_sha`.
- Kernel restarts. All verifier subprocesses for G1, G2 are dead (killed alongside the kernel). The G3 spawn queue entry is gone (in-memory, lost). The G0 witness record persists in `witness_records` (durable in `kernel.db`).
- `reconcile_tasks` runs before IPC listener starts. Task Y transitions `GatesPending → BlockedRecoveryPending`. Audit emits `TaskNeedsRecovery { task_id: Y, prior_state: GatesPending, interrupted_at }`.
- `expire_orphan_verifier_tokens` runs — selects the G1 and G2 token rows (both unconsumed, both `expires_at` still in the future, both for a task now in `BlockedRecoveryPending`). Sets `expires_at = unix_now()` on both. Audit emits two `VerifierTokenOrphaned` events with the original `expires_at` values captured for forensics. Returns `Ok(2)`.
- No record exists for the G3 queued spawn — there was no token row, so nothing to expire. The fact that G3 was wanted will be re-derived by `evaluate_claims` on the next intent.
- Initiative transitions to `Blocked` (no runnable tasks remain).
- Operator runs `raxis-cli task resume Y` → task → `Running`; initiative → `Executing`.
- Operator's planner attaches a session and submits `IntentRequest { task_id: Y, intent_kind: SingleCommit, base_sha, head_sha = (Y's pre-crash evaluation_sha) }`.
- `handlers/intent.rs` runs `evaluate_claims`. For Y's required claim set, the gate evaluation:
  - **G0** — `witness_records` lookup hits; gate satisfied without spawning.
  - **G1, G2** — `witness_records` lookup miss (verifiers died before submitting); fresh verifiers spawned via `spawn_verifier`; new `verifier_run_tokens` rows issued.
  - **G3** — `witness_records` lookup miss; fresh verifier spawned (this is also the path that recovers the lost queue entry — `evaluate_claims` re-derives the gate set from policy + paths and spawns whatever is missing).
- If the cap is now hit, the new spawns queue normally; the queue is fresh in memory.
- Result: `IntentResponse::Accepted { task_state: GatesPending, … }` (assuming gates are still pending). Task progresses through gate evaluation as if the crash never happened, modulo the wasted CPU of the dead verifier subprocesses. **No witness was lost; no gate was double-counted; no zombie token can be honoured even if a stray subprocess somehow survives.**
- Verify: audit log contains `TaskNeedsRecovery { prior_state: GatesPending }`, two `VerifierTokenOrphaned` events, then on resume `TaskTransitioned { from: BlockedRecoveryPending, to: Running, actor: Operator }`, then on first intent the new `VerifierSpawned` events for G1, G2, G3; `witness_records` for G0 is unchanged; the original G1/G2 `verifier_run_tokens` rows have `expires_at` ≤ recovery time and `consumed = 0` (preserved as forensic record per INV-INIT-08).

**Operator abort mid-execution:**
- Initiative in `Executing`; two tasks in `Running`, one `Admitted`.
- Operator runs `raxis-cli initiative abort <id>`.
- All non-terminal tasks → `Cancelled`.
- Initiative → `Aborted`.
- Verify: no task remains in a non-terminal state; budget reservations released; audit log contains `InitiativeAborted`.

**DAG cycle rejection:**
- Plan submitted with A depends on B and B depends on A.
- `create_initiative` fails with `InitiativeError::CyclicDependency`.
- Initiative never created; no task rows written.

**`BlockedRecoveryPending` planner cannot resume:**
- Task in `BlockedRecoveryPending`. Planner submits `IntentRequest` for this task.
- Intent handler: state is not `Running` with matching session and not `Admitted` in `next_ready_tasks` → `HandlerError::TaskNotSchedulable` → dispatcher maps to **`FAIL_TASK_NOT_RUNNING`** (not `FAIL_POLICY_VIOLATION`).
- Only `raxis-cli task resume` (operator) can move the task to `Running`. Verify: no planner-sourced transition to `Running` without operator command.

---

### 4.8 — Trust Invariants (Gap 4)

- **INV-INIT-01:** The planner cannot create or amend tasks. Tasks are instantiated from the signed plan artifact at `approve_plan` time. No planner IPC message results in a new task row.
- **INV-INIT-02:** The planner cannot transition a task to any state other than `Completed` or `Failed`. All other transitions are kernel- or operator-initiated. `transition_task` enforces this via the `TransitionActor` check.
- **INV-INIT-03:** A successor task cannot become schedulable (returned by `next_ready_tasks`) until all its predecessors are `Completed`. `release_successors` is the only mechanism that marks a successor's predecessors as satisfied in the DAG edge table; no state transition occurs on the task row. The planner cannot force a successor to be returned by `next_ready_tasks` before its predecessors complete.
- **INV-INIT-04:** `evaluate_terminal_criteria` is called after **every** `transition_task` write — terminal and non-terminal. It is never called proactively or on a timer. `transition_task` is the single authoritative call-site; `evaluate_terminal_criteria` is never invoked independently by callers. This ensures initiative state (`Executing`, `Blocked`, `Completed`, `Failed`) is always consistent with the task state snapshot after each state change.
- **INV-INIT-05:** A `BlockedRecoveryPending` task can only be resumed (`raxis-cli task resume`) or terminated by operator **`task abort`** (`raxis-cli task abort`). The planner cannot self-resume an interrupted task. The kernel cannot auto-resume without operator approval.
- **INV-INIT-06:** The signed plan artifact is immutable after `approve_plan`. The `terminal_criteria`, task list, and DAG edges cannot be modified in v1. Any change requires a new plan submission and a new `approve_plan` operation.
- **INV-INIT-07:** `RetryTask` (`lifecycle::retry_task`) is the **only** v1 operator-initiated transition out of a terminal task state. It accepts `Failed` only — never `Aborted`, `Cancelled`, or `Completed`. `Aborted` is non-retryable in v1 (the cause was kernel-recorded infrastructure failure or operator abort; re-attempt requires a new initiative). `Cancelled` is non-retryable because the initiative is itself terminal. `Completed` cannot be "un-completed." Combined with INV-INIT-04 (synchronous `evaluate_terminal_criteria` after every `transition_task`), this also bounds when `RetryTask` is meaningfully usable: under `AllTasksSucceeded` the initiative is already terminal by the time the operator could observe the failure, so `retry_task` rejects with `InitiativeTerminal`; under `MinSuccessCount` and `AllTasksTerminal` retries are usable while the initiative remains non-terminal. See §4.5 "Operator decision on partial failure" for the full applicability table.
- **INV-INIT-08:** Gate progress is **always recoverable** from `witness_records` (Table 13) plus the policy artifact, without any in-memory state surviving a crash. The verifier subsystem holds two pieces of in-memory state — the **pending spawn queue** (`gates::verifier_runner::spawn_verifier` step 1) and the **running-verifier counter** — and both are explicitly best-effort: lost on crash, rebuilt as the empty queue + zero counter at startup. The persistent state of "which gates are satisfied for which `(task_id, evaluation_sha)`" lives in `witness_records`; the persistent state of "which gates are required" is computable from `policy_lookup::required_claims` against `task.touched_paths` at any time. After a crash, `recovery::reconcile_tasks` sweeps every non-terminal task to `BlockedRecoveryPending`, `expire_orphan_verifier_tokens` invalidates every unconsumed verifier token whose owning task is now `BlockedRecoveryPending` (defence in depth against stray subprocesses), and operator `task resume` + planner's first post-resume `IntentRequest` re-runs `evaluate_claims` which reads `witness_records` and re-spawns only the still-missing gates' verifiers. This invariant is what makes the "pending spawn queue is in-memory" decision safe: no kernel decision depends on the queue being durable, because every task whose progress depended on it is rebuilt deterministically from durable state on the recovery path.
- **INV-INIT-09:** v1 has **no automatic task-level or initiative-level wall-clock deadline.** Neither `tasks` ([`kernel-store.md`](kernel-store.md) §2.5.1 Table 5) nor `initiatives` (Table 2) carries a `deadline_at` column; no kernel sweep periodically scans non-terminal tasks for elapsed wall-clock time and forces an `Aborted` transition; no `BlockReason::DeadlineExpired` variant exists in §4.4; no `FAIL_TASK_DEADLINE_EXPIRED` planner error code exists in [`peripherals.md`](peripherals.md) §3.1. Task lifetime in v1 is bounded by the seven mechanisms enumerated in §4.5 "Task lifetime bounds (no v1 task-level deadline)" — most importantly lane budget exhaustion (`max_cost_per_epoch` → `FAIL_BUDGET_EXCEEDED`), verifier subprocess rlimits (per-spawn, not per-task), and operator levers (`task abort`, `initiative abort`, `session revoke`). The planner can cooperatively self-deadline by submitting `IntentKind::ReportFailure` (→ `Running → Failed`); this is the v1 equivalent of a deadline. Adding deadline columns, a sweep, the `DeadlineExpired` block reason, the `TaskDeadlineExpired` audit event, and the `FAIL_TASK_DEADLINE_EXPIRED` planner code is a v2 feature documented in §4.5 "v2 plan" — any code or auxiliary doc that asserts a v1 task has a wall-clock deadline is a spec violation.
- **INV-INIT-10 (quarantine — step 10):** A row in `initiative_quarantines` ([`kernel-store.md`](kernel-store.md) §2.5.10 Table 21) freezes its initiative against new `IntentRequest`s. The intent handler's `run_phase_a` runs the quarantine guard at Step 3A — after task lookup (so `task.initiative_id` is known) and after the task-state gate (so an already-Aborted task surfaces the more specific `FAIL_TASK_NOT_RUNNING`). All four `IntentKind` variants (`SingleCommit`, `IntegrationMerge`, `ReportFailure`, `CompleteTask`) hit this gate; quarantine is total. In-flight tasks are NOT aborted — quarantine is a curtain, not a guillotine; use `initiative abort` for the destructive path. Read failures during the quarantine lookup fail closed (the alternative is letting work through past a possibly-quarantined initiative). Quarantine cannot be lifted in v1; an operator who quarantines in error must rebuild the work in a fresh initiative. The companion sweep `OperatorRequest::QuarantinePlansBy { target_fingerprint, reason }` joins on `signed_plan_artifacts.signed_by_fingerprint` (also added in migration 3) to quarantine every initiative an operator approved — used as the immediate containment primitive when an operator key is suspected compromised.
- **INV-INIT-11 (operator-cert four-zone gate — step 6):** Every operator op is gated by `kernel/authority/cert_check::CertEnforcer` against the cert's four-zone status (`raxis_crypto::cert::cert_status`). `Active` and `AlwaysActiveEmergency` allow all `permitted_ops`. `Expiring` allows all ops but emits `OperatorCertExpiringSoon` (deduplicated). `Grace` allows only recovery ops (`AbortTask`, `AbortInitiative`, `RevokeSession`, `DenyEscalation`, `RotateEpoch`); other ops are denied with `OperatorCertExpiredOpDenied`. `Expired` and `NotYetValid` deny all ops. `EmergencyRecovery` certs are structurally pinned to `permitted_ops = ["RotateEpoch"]` and `not_after = 0` (sentinel for "never expires"); any operation they perform also emits `EmergencyOperatorUsed`. Misconfigured certs are loadable only via `--force-misconfig` at policy-sign time, which records `OperatorCertMisconfigBypassed`; the bypass NEVER applies to pubkey/fingerprint or self-signature mismatches. **Cert is mandatory (INV-CERT-01)** — there is no legacy raw-pubkey "no cert installed" branch that bypasses this gate. Loading a `policy.toml` whose `[[operators.entries]]` is missing the `[operators.entries.cert]` sub-table fails serde deserialisation with `missing field "cert"` before the bundle ever reaches `validate_operator_certs`. Existing cert-bearing entries that fail self-sig verification are **always** rejected (no `--force-misconfig` escape hatch).

#### Cross-cutting cert invariants (INV-CERT-01..05)

The cert-mandatory release tightened operator-identity to a single
canonical shape: every operator entry carries a self-signed cert that
the kernel re-verifies on every policy load and re-evaluates against
wall-clock on every operator op. The five INV-CERT-* invariants
below cut across `raxis-policy`, `raxis-store`, `raxis-kernel`, and
`raxis-cli`; they are restated in their respective module specs but
the canonical statement and its justification live here.

- **INV-CERT-01 (cert-mandatory):** Every `[[operators.entries]]`
  block in any policy bundle the kernel will accept carries a
  self-signed `[operators.entries.cert]` sub-table. There is no
  legacy bare-pubkey path. **Enforced at:** `raxis_policy::loader`
  (serde rejects `missing field "cert"` before the bundle is
  constructed); `raxis_genesis_tools::render_genesis_policy_toml`
  (the canonical emitter unconditionally writes the cert sub-table —
  the cert-less branch was deleted); `raxis_kernel::bootstrap`
  (the kernel-side `RAXIS_BOOTSTRAP=1` path uses the same emitter so
  it cannot diverge); `raxis_store::operator_certificates::repopulate`
  (one row per operator entry on every successful epoch advance);
  `raxis_cli::commands::doctor::check_operator_certs` (an empty
  `operator_certificates` table after a successful advance is a
  structural impossibility and surfaces as `[FAIL]`).
  **Justification:** Operator authority is the kernel's single
  authoritative root-of-trust. A cert-less entry would have no
  recoverable display name (audit chain can't say *who* approved a
  plan), no expiry (a leaked key never auto-fails-closed), and no
  declared `permitted_ops` (ambient authority defeats the
  least-privilege model behind the four-zone gate). Making the
  cert mandatory at the loader level pushes detection of the
  problem to the earliest possible moment (loader, not first
  operator op) and makes the absence unforgeable.
  **Scenario:** an operator hand-edits `policy.toml` to remove the
  cert sub-table and re-signs with their key. `policy_load` fails
  with `serde: missing field "cert" for operators.entries[0]`; the
  kernel refuses to advance the epoch; `raxis doctor` (which reads
  `operator_certificates` directly via WAL) prints `[FAIL]
  cert.list: no operator certificates installed (INV-CERT-01)` and
  exits non-zero.

- **INV-CERT-02 (self-signature unforgeable):** Every cert the
  kernel accepts has been verified to be self-signed by the
  Ed25519 key whose public hex equals `cert.pubkey_hex`. **Enforced
  at:** `raxis_crypto::cert::verify_cert_self_signature`
  (cryptographic check); `raxis_policy::bundle::validate_operator_certs`
  (called on every policy load — there is no `--force-misconfig`
  bypass for this check); `raxis_cli::commands::cert::run` (every
  install path verifies before splicing); `raxis_cli::commands::genesis::run`
  (both `--operator-cert` and `--operator-key` paths verify before
  embedding). **Justification:** A cert is the operator's claim
  about their own pubkey, validity window, and permitted ops; if
  the self-signature could be forged or skipped, an attacker who
  controlled the policy file could reissue an arbitrary cert
  bearing the victim operator's pubkey and grant themselves any
  `permitted_ops` they liked. Pinning self-signature verification
  as the **only** unbypassable cert invariant (structural failures
  are bypassable via `--force-misconfig`) keeps the trust root
  cryptographically anchored even when operators need to ship
  partially-misconfigured certs in emergencies.
  **Scenario:** an attacker with write access to `policy.toml`
  copies a victim operator's cert, changes `permitted_ops` to add
  `RotateEpoch`, and re-bumps the file. `validate_operator_certs`
  recomputes the canonical cert bytes, runs `Verify` against the
  edited cert's `self_sig_hex` field, and rejects the load with
  `OperatorCertSelfSigInvalid`. No `--force-misconfig` flag relaxes
  this check. The attacker would need the operator's private key,
  at which point they already have everything.

- **INV-CERT-03 (private key never persisted):** No CLI command
  ever writes operator private-key bytes to `<data_dir>` or any
  other persistent location. Private keys are read into process
  memory exclusively for the in-process `sign_cert` /
  `sign_policy` calls, then dropped. **Enforced at:**
  `raxis_cli::commands::genesis::run` (the `--operator-key` path
  loads the key with `signing::load_operator_key`, uses it for
  `sign_cert`, and never serialises the secret bytes; a CLI test
  asserts this with a recursive seed-leakage scan over `<data_dir>`
  after `genesis` completes); `raxis_cli::commands::cert::run`
  (cert install paths only consume `*.cert.toml`, never private
  PEM); `raxis_cli::commands::policy::sign` (private key is the
  sole input that does not get written back to disk). **The
  kernel itself never sees the operator private key on any path**
  — the operator key lives only on the operator's machine (or
  whatever air-gapped device minted the cert).
  **Justification:** The operator key is the apex of the trust
  chain — losing it means losing the ability to sign new policy
  bundles and (worse) means an attacker who exfiltrates the data
  directory could mint policy bundles indistinguishable from the
  legitimate operator. Refusing to write private bytes anywhere
  the kernel manages keeps the blast radius of a `<data_dir>`
  compromise bounded to "attacker can read public keys, certs,
  and audit log" — none of which lets them spoof an operator.
  **Scenario:** a misconfigured backup tool snapshots `<data_dir>`
  to an off-host destination. Even if the snapshot leaks publicly,
  the operator's private key is not in it; the attacker cannot
  sign a fresh policy bundle, cannot mint an `OperatorCert` bound
  to the operator's pubkey (cert self-signature would not verify
  against any key the attacker controls), and the kernel will
  refuse any policy load whose `operator_signature_hex` was not
  produced by the legitimate operator key.

- **INV-CERT-04 (rotation pubkey continuity):** When `raxis cert
  install --replace-for <fp> --new-cert <path>` rotates a cert,
  the new cert's `pubkey_hex` MUST equal the old cert's
  `pubkey_hex`. A pubkey change is a different operator entirely
  and goes through `policy sign` + `epoch advance` instead.
  **Enforced at:** `raxis_cli::commands::cert::run` (the rotation
  path loads the existing cert by `--replace-for` fingerprint,
  compares `pubkey_hex` to the new cert, and aborts with a hard
  error on mismatch — there is no `--force-misconfig` bypass for
  this check); audited via
  `AuditEventKind::OperatorCertInstalled.previous_fingerprint =
  Some(<old fp>)`. **Justification:** A "cert rotation" semantically
  means *the same operator extending their identity* — new
  validity window, possibly trimmed `permitted_ops`, possibly a
  new display name. Allowing the pubkey to change under a
  rotation would let an attacker (or careless operator) silently
  swap one operator for another while the audit chain reads
  "rotation, not a new operator," obscuring the change of
  authority. Pinning pubkey continuity makes the audit chain
  unambiguous: if the audit log shows
  `OperatorCertInstalled.previous_fingerprint = Some(X)`, the
  reader can rely on the new and old certs sharing a key.
  **Scenario:** an operator wants to "rotate" Chika's cert to
  Jinanwa's key. `cert install --replace-for <chika-fp> --new-cert
  jinanwa.cert.toml` rejects with `OperatorCertPubkeyMismatch`
  before splicing; the operator must instead remove Chika's
  entry, add Jinanwa's entry, re-sign the policy, and advance the
  epoch — all of which produce loud audit events
  (`OperatorCertInstalled` for Jinanwa with no `previous_fingerprint`,
  not a rotation rollup).

- **INV-CERT-05 (audit chain captures every cert event):** Every
  state transition involving an operator cert produces an audit
  event on the chain — install, rotation, structural bypass,
  expiry-window crossing, expired-op denial, emergency use.
  **Enforced at:** `raxis_kernel::ipc::operator::emit_cert_chain_mirror`
  (called from epoch-advance dispatch; emits
  `OperatorCertInstalled` per cert with `previous_fingerprint`
  populated when the prior bundle held a cert for the same
  pubkey, plus `OperatorCertMisconfigBypassed` per
  `force_misconfig_bypass = true` entry); `CertEnforcer` (emits
  `OperatorCertExpiringSoon` deduplicated per `(fp, day)`,
  `OperatorCertExpiredOpDenied` per denied op,
  `EmergencyOperatorUsed` per emergency-cert op). **Justification:**
  The audit chain is the kernel's single source of forensic
  truth; if a cert event went unrecorded, an investigator could
  not reconstruct who held authority at any historical moment.
  Emitting per-event (rather than per-policy-load) keeps the
  granularity high enough to answer "did Chika's cert grant
  permission to *this specific approval*?" rather than just "was
  Chika's cert installed at any point?". The
  `previous_fingerprint` field on `OperatorCertInstalled` makes
  rotations unambiguously traceable end-to-end.
  **Scenario:** an investigator pulls the audit chain six months
  later and asks "who was the active Chika cert at timestamp T?"
  They `grep OperatorCertInstalled` for Chika's pubkey, sort by
  audit chain index, walk the `previous_fingerprint` chain
  forward to T, and arrive at exactly one cert fingerprint — the
  one in force at that moment. No combination of (no-op
  rotations, structural bypass, expiry crossings, emergency
  uses) is invisible to this walk.

---

> **End of Part 2.4.**
> Gap 4 completes the core kernel FSM specifications (Gaps 1–4). Part 2.5 closes the remaining Part 2 gaps — store DDL, plan artifact signing contract, key inventory, operator authentication protocol, and [[gates]] normative schema — before Part 3 begins.

---

