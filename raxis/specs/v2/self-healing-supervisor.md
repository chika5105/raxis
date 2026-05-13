# Self-healing supervisor — kernel restart contract

> **Status:** V2.5 normative. Lands behind the
> `RAXIS_SUPERVISOR_AUTO_RESTART=1` opt-in until 30 days of
> production observation; default behaviour is unchanged (kernel
> exits, operator restarts manually). Live-e2e DOES NOT set the
> opt-in env var.
>
> **Cross-references:**
> - `concurrency-and-locking.md §7a` — the in-kernel
>   `runtime-deadlock-detection` watcher this surface composes with
>   (`INV-LOCK-07`).
> - `audit-paired-writes.md` — the audit-emission contract this
>   surface extends with the four new restart-lifecycle event kinds.
> - `dashboard-hardening.md` — the operator-dashboard surface
>   contract; this spec adds the kernel-lifecycle banner.
> - `kernel-lifecycle.md` — the boot/shutdown flow this surface
>   composes with on the kernel side (Step 6 recovery sweep).
> - `invariants.md` — adds `INV-SUPERVISOR-RESTART-AUDIT-01`,
>   `INV-SUPERVISOR-CIRCUIT-BREAKER-01`, `INV-SUPERVISOR-OPT-IN-01`,
>   `INV-DASHBOARD-KERNEL-LIFECYCLE-01`,
>   `INV-SUPERVISOR-SIGTERM-RESPECT-01`,
>   `INV-SUPERVISOR-SIGINT-RESPECT-01`,
>   `INV-SUPERVISOR-EXIT-CODE-CLASSIFICATION-01`,
>   `INV-SUPERVISOR-SHUTDOWN-GRACE-01`.
> - `guides/operator/19-supervisor-and-restart.md` — operator
>   recipe for the opt-in env var, circuit-breaker reset, and
>   shutdown signal contract.

---

## §1 — Pros (why this surface exists)

| # | Pro | Concrete payoff |
|---|---|---|
| 1.1 | **Production resilience.** | A deadlock during long-running ops doesn't permanently brick the kernel — the supervisor restarts within ~3 s of the watcher's `process::exit(70)`. |
| 1.2 | **Operator visibility.** | Dashboard shows `Restarting (attempt N/3)` instead of an opaque hang; the operator's mental model matches the kernel's actual state. |
| 1.3 | **Mechanical audit trail.** | Every restart emits `KernelDeadlockDetected` (or matching crash-class event) → `KernelRestartInitiated` → `KernelRestartCompleted` (or `KernelRestartHaltedCircuitOpen`). The pair is hash-chain continuous across the restart boundary. |
| 1.4 | **Fewer 2 a.m. pages.** | Transient deadlocks observed in iter15 / iter16 were single-shot; circuit-breaker-bounded auto-restart absorbs them without an operator page while still flagging the underlying bug for next-day forensics. |
| 1.5 | **Composable with existing host-supervisor patterns.** | Same approach as `cargo xtask hygiene-check` / disk-pressure preflight: opt-in, audited, structured failure surface. Future `system-daemon` work composes via launchd / systemd. |
| 1.6 | **Uniform handling for all unclean exits.** | Deadlock (exit 70), panic (exit ≠ 0), OOM-kill (signaled), SIGSEGV / SIGBUS / SIGABRT all flow through the same supervisor decision path; one code surface, not four. |

---

## §2 — Cons + risks (mitigations are mandatory, not optional)

| # | Risk | Mitigation |
|---|---|---|
| 2.1 | **Masks real bugs.** | Auto-restart can hide the underlying deadlock. *"Transient" is dangerous framing — there are no transient deadlocks, only repeating ones we haven't reproduced reliably.* **Mitigation:** every restart writes a forensic dump (`<data_dir>/deadlock_dump_<unix_ts>.json`) carrying the full `parking_lot::deadlock::check_deadlock()` lock-graph (thread IDs, lock IDs, backtraces). Dump is read on the next boot to synthesise `KernelDeadlockDetected` into the audit chain. **No deadlock is silently absorbed.** Kernel notification surface routes this event at `Critical` severity. |
| 2.2 | **Loses in-flight work.** | Session VMs in flight when kernel restarts may be orphaned. **Mitigation:** the audit chain + SQLite persistence let `recovery::reconcile` rehydrate FSM state on restart (the existing crash-recovery sweep that runs at every boot today, kernel-core.md §2.2 Step 6). Orphan VMs are reaped by the substrate's existing TTL (`extensibility-traits.md §3.5`). |
| 2.3 | **Audit-chain hash continuity.** | Restart needs to preserve `prev_sha256` continuity across the boundary. **Mitigation:** the kernel writes a terminal record on its way out (`KernelDeadlockDetected` from the watcher's *best-effort* attempt — see §3.2; or a clean `KernelStopped` on operator exit). The next boot's first chained record is `KernelRestartCompleted` with `prev_sha256` = the last record on disk (which the existing chain-resume path in `kernel/src/main.rs` already computes via `last_chain_state`). The offline `verify-chain` walker stays clean. |
| 2.4 | **State-recovery complexity.** | Half-committed SQLite transactions, dangling FDs, in-flight planner sessions. **Mitigation:** kernel's existing crash-recovery sweep (`recovery::reconcile`) handles this — it is invoked at boot today; the restart path just re-enters the same sweep. No new recovery code is introduced by this spec. |
| 2.5 | **Restart loops.** | A persistent deadlock would cause a crash-loop. **Mitigation:** circuit breaker — `≤ 3 restarts in a 60-second sliding window`, then escalate to `Halted (circuit-open)` and refuse to restart further until operator runs `raxis-supervisor reset-circuit-breaker`. (`INV-SUPERVISOR-CIRCUIT-BREAKER-01`.) |
| 2.6 | **Mechanism vs root cause.** | Production should *prevent* deadlocks via `INV-LOCK-01..07`, not paper over them. **Mitigation:** every restart emits a `Critical`-severity audit event AND writes a forensic lock-graph dump engineers can analyse post-hoc to fix the underlying deadlock. Default-off opt-in (`RAXIS_SUPERVISOR_AUTO_RESTART=1`) ensures dev / live-e2e still surfaces every wedge as a hard exit (no auto-restart can mask a regression). |
| 2.7 | **Complexity vs invariant integrity.** | The supervisor adds a new failure surface — supervisor bugs are now possible. **Mitigation:** the supervisor crate is small (target ≤ 500 LOC), single-responsibility (spawn child / classify exit / decide restart), has its own witness tests (one per row of the §4.4 exit-code table), opt-in via env var initially, and the kernel's existing audit chain is the source of truth for what happened (the supervisor's structured stderr log is forensic evidence, not authoritative). |
| 2.8 | **Half-flushed audit writes.** | A deadlocked kernel might be holding the audit-write mutex when the watcher fires — emitting `KernelDeadlockDetected` *through* the audit pipeline could deadlock the watcher itself. **Mitigation:** the watcher writes its forensic dump to a sibling file (`<data_dir>/deadlock_dump_<unix_ts>.json`) WITHOUT going through the kernel's own audit machinery. The supervisor reads the dump on the next boot and the kernel synthesises `KernelDeadlockDetected` into the chain AFTER the recovery sweep completes (so the chain hash stays continuous and the audit-write mutex is freshly initialised). The watcher's *best-effort* in-process emit is allowed but never depended on. |
| 2.9 | **Supervisor masks operator intent.** | This is among the worst UX bugs a self-healing system can have: turning `Ctrl+C` into "stop, then auto-restart 200 ms later" is infuriating, hard to diagnose, and erodes trust. It also breaks OS-level service management — `launchctl stop` and `systemctl stop` both send `SIGTERM`, and the supervisor MUST honour that for the deferred `system-daemon` work to compose. **Mitigation:** the operator-signal contract in §4.4 — supervisor installs SIGTERM / SIGINT handlers, sets an `intentional_shutdown` flag, forwards the signal to the kernel, waits up to `RAXIS_SUPERVISOR_SHUTDOWN_GRACE_SECS` (default 30 s), and never restarts after a SIGTERM / SIGINT exit (regardless of whether the supervisor or an external actor sent the signal). Witness invariants `INV-SUPERVISOR-SIGTERM-RESPECT-01` / `INV-SUPERVISOR-SIGINT-RESPECT-01` / `INV-SUPERVISOR-EXIT-CODE-CLASSIFICATION-01` / `INV-SUPERVISOR-SHUTDOWN-GRACE-01` make it mechanically enforced. |

---

## §3 — Tier 1 (in-kernel, ALWAYS-ON when `runtime-deadlock-detection` is on)

### §3.1 Forensic-dump writer

New module `raxis/kernel/src/deadlock_dump.rs`:

* Pure file-write API (`write_dump(data_dir: &Path, dump: &DeadlockDump) -> std::io::Result<PathBuf>`).
* No dependency on `raxis_audit_tools::AuditSink` / `raxis_store::Store` / `parking_lot::Mutex` — the writer must be safe to call from the watcher thread even when every other kernel mutex is wedged.
* Atomic write: `tempfile + rename` so a partial dump never lands under a final name.
* Dump filename: `<data_dir>/deadlock_dump_<unix_ts>.json`.
* Dump payload (`DeadlockDump`):
  ```json
  {
    "kernel_version": "0.1.0",
    "detected_at_unix_secs": 1714500000,
    "cycle_count": 1,
    "thread_count": 4,
    "lock_count": 3,
    "cycles": [
      {
        "cycle_index": 0,
        "threads": [
          { "thread_id": "ThreadId(7)", "backtrace": "..." },
          { "thread_id": "ThreadId(11)", "backtrace": "..." }
        ]
      }
    ]
  }
  ```

### §3.2 Wire `spawn_deadlock_watcher` to dump + exit 70

`kernel/src/main.rs::spawn_deadlock_watcher` is extended (the existing
JSON-line stderr emit per `concurrency-and-locking.md §7a` stays — it
is forensic evidence and is independent of dump writing):

1. Build the `DeadlockDump` from the `parking_lot::deadlock::check_deadlock()` result.
2. Call `deadlock_dump::write_dump(&data_dir, &dump)`. **Best-effort** — disk-full / EROFS does not block exit; the structured stderr line is the fallback.
3. Call `std::process::exit(70)` (custom exit code; see §4.4 row "WEXITSTATUS = 70"). Replaces the current `panic!` so:
    * The kernel exits with a stable, supervisor-recognised code (vs whatever `panic = "abort"` happens to produce on the host).
    * The exit reason is structurally legible to the supervisor without parsing stderr.
    * The pre-existing `panic!` semantics (non-zero exit, `panic = "abort"`) are preserved as a fallback in tests that don't link the dump writer (the `#[ignore]`-by-default self-test still works).

The 2-second cadence and the per-cycle stderr lines are unchanged — this spec **adds** dump-write + structured-exit on top.

### §3.3 Boot-time dump rehydration

`kernel/src/main.rs` boot sequence (between Step 6 `recovery::reconcile`
and Step 7a `AuditWriter::open`) gains a new step:

* Scan `<data_dir>/deadlock_dump_*.json` for files newer than the most recent `KernelStarted` event (so we don't re-emit dumps the previous boot already chained).
* For each unprocessed dump, after the `AuditWriter` is open:
  1. Emit `KernelDeadlockDetected { thread_count, lock_count, dump_path, detected_at_unix_secs }` via `inner_audit.emit(...)`.
  2. Emit `KernelRestartCompleted { prev_run_exit_code: 70, recovery_sweep_ms, dump_path: Some(...) }` after Step 8 `KernelStarted` lands.
  3. Move the dump to `<data_dir>/deadlock_dumps_consumed/<filename>` (NOT delete — operator forensics relies on the file persisting; the rename moves it out of the rehydration scan path).

For unclean exits **without** a dump (panic, OOM-kill, SIGSEGV, signaled), the supervisor's sentinel file (§4.5) carries the prior exit class; the kernel emits `KernelRestartCompleted { prev_run_exit_code, recovery_sweep_ms, dump_path: None }` after a successful boot. The `KernelDeadlockDetected` event is conditional on `dump_path: Some(...)`.

### §3.4 New audit event variants

In `raxis/crates/audit/src/event.rs::AuditEventKind`:

```rust
KernelDeadlockDetected {
    /// Total threads across all detected cycles.
    thread_count: u32,
    /// Total locks across all detected cycles.
    lock_count: u32,
    /// Forensic dump path the kernel wrote on its way out
    /// (`<data_dir>/deadlock_dump_<unix_ts>.json`). Always set
    /// when this event is synthesised on the next boot from a
    /// dump file; `None` only for the *best-effort* in-process
    /// emit the watcher attempts (which is itself best-effort
    /// and may not land if the audit pipeline is wedged).
    dump_path: Option<String>,
    /// Unix-seconds wallclock the watcher detected the cycle
    /// at. For the next-boot synthesised event this comes from
    /// the dump file; for the in-process best-effort emit it
    /// is `unix_now_secs()`.
    detected_at_unix_secs: i64,
}

KernelRestartInitiated {
    /// Stable, PascalCase reason string. One of:
    ///   * `"DeadlockDetected"`
    ///   * `"PanicAbort"` — non-zero exit code that wasn't 70
    ///   * `"SignalCrash"` — SIGSEGV / SIGBUS / SIGABRT
    ///   * `"OomKilled"` — SIGKILL, supervisor did NOT send
    ///                     (best-effort distinction; treated as
    ///                     external if the supervisor flag is
    ///                     unset)
    reason: String,
    /// Numeric exit status the supervisor observed
    /// (`WEXITSTATUS` for clean exits, `128 + signal` for
    /// signaled exits — matches the shell convention).
    prev_run_exit_code: i32,
    /// 1-indexed restart attempt within the current circuit-
    /// breaker window. The first restart after a clean run
    /// resets the counter to 1.
    attempt_n: u32,
    /// Operator-policy ceiling at the time of this restart
    /// (`SUPERVISOR_RESTART_MAX_ATTEMPTS`, default 3). Recorded
    /// so dashboards can render "attempt 2 of 3" without
    /// re-reading the policy snapshot.
    max_attempts: u32,
}

KernelRestartCompleted {
    /// Exit status of the previous run that triggered this
    /// restart. Same encoding as `KernelRestartInitiated`.
    prev_run_exit_code: i32,
    /// Wall-clock duration of the boot-time crash-recovery
    /// sweep (`recovery::reconcile` Steps 6 + 8a). Useful for
    /// post-restart latency budgeting.
    recovery_sweep_ms: u64,
    /// Forensic dump that triggered this restart, if the cause
    /// was a deadlock detection on the prior run. `None` for
    /// crash / OOM / signaled prior runs.
    dump_path: Option<String>,
}

KernelRestartHaltedCircuitOpen {
    /// Number of restart attempts the supervisor observed in
    /// the sliding window before refusing further restarts.
    attempts_in_window: u32,
    /// Sliding-window width in seconds (default 60).
    window_secs: u32,
    /// Stable, PascalCase classification of the most recent
    /// failure that tripped the breaker. Same set as
    /// `KernelRestartInitiated.reason`.
    last_failure_reason: String,
}
```

All four are routed through `notification_priority` in `crates/dashboard-kernel/src/notification_filter.rs`:

| Event kind | Notification priority | Rationale |
|---|---|---|
| `KernelDeadlockDetected` | `Critical` | Forensic-grade lock-graph; engineers must look. |
| `KernelRestartInitiated` | `High` | Operator should know the kernel is about to be replaced. |
| `KernelRestartCompleted` | `Medium` | Steady-state observability; not a page. |
| `KernelRestartHaltedCircuitOpen` | `Critical` | Manual intervention required; this IS a 2 a.m. page. |

---

## §4 — Tier 2 (external supervisor binary, OPT-IN)

### §4.1 Crate layout

New crate `raxis/crates/supervisor/`:

```
crates/supervisor/
├── Cargo.toml                   # raxis-supervisor binary + lib
├── src/
│   ├── lib.rs                   # public API: SupervisorConfig, run()
│   ├── main.rs                  # CLI dispatch (start / stop / status / reset-circuit-breaker)
│   ├── circuit_breaker.rs       # sliding-window restart counter + persistence
│   ├── sentinel.rs              # KernelLifecycleStatus + atomic write
│   ├── child.rs                 # tokio::process::Command spawn + wait
│   ├── classify.rs              # exit-code → SupervisorAction (the §4.4 table)
│   ├── signal.rs                # SIGTERM / SIGINT handler + intentional_shutdown flag
│   └── log.rs                   # structured stderr log (kernel-shaped JSON lines)
└── tests/
    ├── exit_classification.rs   # one test per row of the §4.4 table
    ├── circuit_breaker.rs       # 4 restarts in 60s → halt-circuit-open
    ├── sentinel_round_trip.rs   # write + read sentinel atomically
    ├── sigterm_respect.rs       # INV-SUPERVISOR-SIGTERM-RESPECT-01
    ├── sigint_respect.rs        # INV-SUPERVISOR-SIGINT-RESPECT-01
    └── shutdown_grace.rs        # INV-SUPERVISOR-SHUTDOWN-GRACE-01
```

### §4.2 Spawn + wait loop

```text
loop {
    sentinel.write(KernelLifecycleStatus::Healthy { booted_at_unix_secs: now });
    let outcome = spawn_kernel_and_wait().await;
    let action = classify(outcome, intentional_shutdown.load());
    match action {
        SupervisorAction::Restart { reason } => {
            if !circuit_breaker.allow_restart(now) {
                sentinel.write(KernelLifecycleStatus::Halted {
                    sub_state: HaltedSubState::CircuitOpen,
                    last_restart_unix_ts: now,
                    last_restart_reason: reason,
                    attempts_in_window: circuit_breaker.recent_count(),
                });
                exit(0); // supervisor exits cleanly; operator must reset
            }
            sentinel.write(KernelLifecycleStatus::Restarting {
                reason: reason.clone(),
                attempt_n: circuit_breaker.attempt_n(),
                max_attempts: SUPERVISOR_RESTART_MAX_ATTEMPTS,
                last_restart_unix_ts: now,
            });
            // No sleep — the kernel's own boot is the throttle. The
            // circuit breaker bounds total attempts.
            continue;
        }
        SupervisorAction::Halt { sub_state } => {
            sentinel.write(KernelLifecycleStatus::Halted {
                sub_state,
                last_restart_unix_ts: now,
                last_restart_reason: outcome.classification_reason(),
                attempts_in_window: circuit_breaker.recent_count(),
            });
            exit(0);
        }
    }
}
```

### §4.3 Circuit breaker

* Sliding window: `60 seconds` (`SUPERVISOR_RESTART_WINDOW_SECS`).
* Max attempts in window: `3` (`SUPERVISOR_RESTART_MAX_ATTEMPTS`).
* Persisted state file: `<data_dir>/supervisor_state.json`:
  ```json
  {
    "schema_version": 1,
    "recent_restarts": [
      { "unix_ts": 1714500000, "reason": "DeadlockDetected" },
      { "unix_ts": 1714500015, "reason": "DeadlockDetected" }
    ],
    "circuit_open_at_unix_ts": null
  }
  ```
* Reset path: `raxis-supervisor reset-circuit-breaker` truncates `recent_restarts` and clears `circuit_open_at_unix_ts`. Requires `--yes` or interactive `y/N` confirmation.
* On supervisor restart (e.g. a launchd respawn of the supervisor itself), the file is read at startup so the breaker survives supervisor restarts — operator intent persists across both layers.

### §4.4 Exit-code classification (`INV-SUPERVISOR-EXIT-CODE-CLASSIFICATION-01`)

The supervisor classifies each kernel exit per the table below.
The `intentional_shutdown` flag is the source of truth for any
signaled exit: any kernel exit observed after this flag is true is
operator-intent regardless of underlying exit code.

| Child outcome | Supervisor sent the signal? | Action | Sentinel state | Rationale |
|---|---|---|---|---|
| `WEXITSTATUS = 0` | n/a | **NO restart** | `Halted (clean)`, supervisor exit 0 | operator-initiated clean shutdown via `raxis` CLI / IPC |
| `WEXITSTATUS = 70` | n/a | restart with circuit breaker | `Restarting (DeadlockDetected)` | deadlock detector tripped (§3.2) |
| `WEXITSTATUS != 0 && != 70` | n/a | restart with circuit breaker | `Restarting (PanicAbort)` | unexpected crash (panic, abort, BOOT_ERR_*) |
| `WIFSIGNALED + SIGTERM` | YES (operator → supervisor → kernel) | **NO restart** | `Halted (operator-terminated)`, supervisor exit 0 | operator-initiated, loop completes |
| `WIFSIGNALED + SIGTERM` | NO (external init system / `kill -TERM`) | **NO restart** | `Halted (external-sigterm)`, supervisor exit 0 | external actor killed kernel; treated as operator intent |
| `WIFSIGNALED + SIGINT` | n/a (universally Ctrl+C) | **NO restart** | `Halted (operator-interrupt)`, supervisor exit 0 | SIGINT is universally Ctrl+C; never restart |
| `WIFSIGNALED + SIGKILL` | NO (someone went `kill -9`) | **NO restart** | `Halted (external-sigkill)`, supervisor exit 0 | someone bypassed graceful shutdown; never undo |
| `WIFSIGNALED + SIGKILL` | YES (shutdown-grace-timeout escalation) | per the original cause | `Restarting` or `Halted` | the SIGKILL was the supervisor's escalation step; classification follows the original cause that started the shutdown. If `intentional_shutdown == true`, halt; else, treat as crash and restart. |
| `WIFSIGNALED + SIGABRT/SIGSEGV/SIGBUS` | n/a | restart with circuit breaker | `Restarting (SignalCrash)` | kernel crashed itself; same path as exit 70 |
| `WIFSIGNALED + SIGHUP` | n/a | log + ignore for now | unchanged | reserved for forward-compat "reload config"; not a restart trigger, not a shutdown trigger |
| `WIFSIGNALED + any other signal` | n/a | restart with circuit breaker | `Restarting (SignalCrash)` | conservative: any unrecognised signal that killed the kernel is treated as a crash |

### §4.5 Operator-signal contract (`INV-SUPERVISOR-SIGTERM-RESPECT-01`, `INV-SUPERVISOR-SIGINT-RESPECT-01`, `INV-SUPERVISOR-SHUTDOWN-GRACE-01`)

The supervisor installs handlers for `SIGTERM`, `SIGINT`, and `SIGHUP` BEFORE spawning the kernel child:

1. **`SIGTERM` / `SIGINT` received.** Atomically set:
    * `intentional_shutdown = true`
    * `signal_origin = "operator-terminated"` (for SIGTERM) or `"operator-interrupt"` (for SIGINT)
2. **Forward** the signal to the kernel child via `nix::sys::signal::kill(child_pid, signal)`. The kernel's own signal handlers (`signal::ctrl_c` in `kernel/src/main.rs`) flow the shutdown through `dashboard::DashboardServer::serve_with_shutdown` and the IPC graceful-drain seam (`dashboard-hardening.md §1.5`).
3. **Wait** up to `RAXIS_SUPERVISOR_SHUTDOWN_GRACE_SECS` (default `30`) for the kernel to exit naturally.
4. **Escalation.** If the grace deadline expires AND the kernel is still alive:
    * Log a structured `KernelGracefulShutdownTimedOut { grace_secs, child_pid }` line on supervisor stderr.
    * Send `SIGKILL` to the kernel child. (Per §4.4 row "supervisor SENT SIGKILL", classification follows the original cause — `intentional_shutdown == true` → halt.)
5. **Wait** for the kernel exit, classify per the §4.4 table, write the final sentinel state, supervisor exits `0`.
6. **`SIGHUP`** is logged + ignored. Forward-compat reserved for "reload config".

The `intentional_shutdown` flag is **load-bearing**: any kernel exit observed after it flips to `true` is operator-intent, regardless of the kernel's actual exit code (a kernel that segfaults in the middle of its graceful-shutdown cleanup still classifies as a `Halted` outcome, not `Restarting (SignalCrash)`, because the operator has already declared intent).

### §4.6 Sentinel file

Path: `<data_dir>/kernel_lifecycle_status.json`. Atomic write via `tempfile + rename`. Schema:

```json
{
  "schema_version": 1,
  "status": "Healthy" | "Restarting" | "Halted",
  "sub_state": "Clean" | "OperatorTerminated" | "OperatorInterrupt"
              | "ExternalSigterm" | "ExternalSigkill" | "CircuitOpen"
              | null,
  "attempt_n": 0,
  "max_attempts": 3,
  "last_restart_unix_ts": 0,
  "last_restart_reason": null,
  "attempts_in_window": 0,
  "window_secs": 60,
  "supervisor_pid": 12345,
  "kernel_pid": 12346,
  "updated_at_unix_secs": 1714500000
}
```

* `status = "Healthy"`: the kernel child is alive; `kernel_pid` carries the live PID.
* `status = "Restarting"`: the kernel exited and the supervisor is about to spawn a replacement; `last_restart_reason` carries the §4.4 classification.
* `status = "Halted"`: the supervisor has decided not to restart; `sub_state` carries which row of the §4.4 table caused the halt.

### §4.7 Stderr log

Same JSON-line format as the kernel's stderr (so `live-e2e/src/inspect_iter.sh` and the `iter*.log` consumers can read both). Path: `<data_dir>/supervisor.stderr.log`.

Example lines:

```json
{"level":"info","event":"KernelChildSpawned","pid":12346,"attempt_n":1}
{"level":"info","event":"KernelChildExited","exit_status":"WEXITSTATUS=70","action":"Restart","reason":"DeadlockDetected"}
{"level":"warn","event":"CircuitBreakerCheck","attempts_in_window":2,"max_attempts":3,"window_secs":60}
{"level":"error","event":"CircuitBreakerOpen","attempts_in_window":3,"window_secs":60,"last_failure_reason":"DeadlockDetected"}
{"level":"info","event":"OperatorSignalReceived","signal":"SIGTERM","action":"forward_to_kernel"}
{"level":"warn","event":"KernelGracefulShutdownTimedOut","grace_secs":30,"child_pid":12346,"action":"escalate_to_sigkill"}
```

### §4.8 CLI

```text
raxis-supervisor start --data-dir <path>
raxis-supervisor stop
raxis-supervisor stop --force
raxis-supervisor status
raxis-supervisor reset-circuit-breaker [--yes]
```

* `start` — spawn the supervisor as a foreground process. Writes its own PID to `<data_dir>/supervisor.pid` so `stop` can find it without an environment dance. Spawns the kernel child, enters the §4.2 loop. Honours `RAXIS_SUPERVISOR_AUTO_RESTART=1` (default off; without it the supervisor logs a one-line warning and exits `0` immediately, leaving operator-managed restart unchanged — this is the `INV-SUPERVISOR-OPT-IN-01` gate).
* `stop` — read `<data_dir>/supervisor.pid`, send `SIGTERM` to the supervisor PID. The supervisor's signal handler (§4.5) takes over from there.
* `stop --force` — same as `stop`, but if the kernel is still alive after `5` seconds, escalate to `SIGKILL` to the supervisor (which forwards to the kernel). Tightens the §4.5 grace deadline for the urgent-shutdown case.
* `status` — read `<data_dir>/kernel_lifecycle_status.json` + `<data_dir>/supervisor_state.json`, print a human-readable summary of (a) the current sentinel state, (b) the circuit-breaker state, (c) the last 10 restart timestamps + reasons.
* `reset-circuit-breaker` — operator override: clear `recent_restarts` + `circuit_open_at_unix_ts` in `supervisor_state.json`. Requires `--yes` or interactive `y/N` confirmation. Emits a structured supervisor log line `{"event":"CircuitBreakerReset","operator":"<uid>"}`.

### §4.9 Opt-in (`INV-SUPERVISOR-OPT-IN-01`)

Phase 1 (this PR): default behaviour unchanged. Without `RAXIS_SUPERVISOR_AUTO_RESTART=1`, the supervisor binary refuses to enter the §4.2 spawn-and-watch loop, exits `0`, and the operator's existing `raxis-kernel` invocation runs unchanged. Live-e2e (`raxis/live-e2e/...`) does NOT set the env var; iter41+ behaviour is bit-identical.

Phase 2 (post-working live-e2e, separate PR): flip default-on for production deployments (launchd plist, systemd unit).

Phase 3 (after 30 days observation): consider removing the opt-in gate entirely.

---

## §5 — Tier 3 (dashboard surface)

### §5.1 Wire shape

New endpoint `GET /api/health/kernel-lifecycle`. Wire shape mirrors the on-disk sentinel + adds derived fields:

```json
{
  "fresh": true | false,
  "status": "Healthy" | "Restarting" | "Halted",
  "sub_state": "Clean" | "OperatorTerminated" | "OperatorInterrupt"
              | "ExternalSigterm" | "ExternalSigkill" | "CircuitOpen"
              | null,
  "attempt_n": 0,
  "max_attempts": 3,
  "last_restart_unix_ts": 0,
  "last_restart_reason": null,
  "attempts_in_window": 0,
  "window_secs": 60,
  "supervisor_pid": 12345,
  "kernel_pid": 12346,
  "updated_at_unix_secs": 1714500000
}
```

`fresh = true` when the sentinel file has been updated within the last `15` seconds (a stale sentinel implies the supervisor itself is wedged or absent — render as `Halted (sentinel-stale)` operator-side).

### §5.2 Handler

New axum handler in `raxis/crates/dashboard/src/routes/health.rs`: `GET /api/health/kernel-lifecycle`.

* Auth: `read` role (same as `/api/health/subsystems`).
* Source: reads `<data_dir>/kernel_lifecycle_status.json` directly (NOT a kernel IPC call — the kernel may be down during restart, so the dashboard sources from the supervisor's sentinel).
* If the sentinel file is missing OR malformed: returns `status = "Healthy", sub_state = null, fresh = false` (so a kernel started without the supervisor still renders sensibly — operator just doesn't get the restart-aware banner). Logs a `dashboard_kernel_lifecycle_sentinel_missing` warn line.
* If the sentinel file is older than 15 s: returns the parsed status with `fresh = false` (FE renders the banner with a "supervisor sentinel stale" annotation).
* Audit: emits `OperatorHealthQueried` per `INV-AUDIT-OPERATOR-ACTION-01` (same code path as `/api/health/subsystems`).

### §5.3 React component

New `KernelLifecycleBanner.tsx` in `raxis/dashboard-fe/src/components/banners/`. Mounted in `Shell.tsx` immediately above the main content area (mirroring where `ChainStatusBanner` is mounted on the Audit page; this banner lives in the global shell because operator-relevant kernel-state is global).

Per-state render contract:

| status / sub_state | Tone | Headline | Detail |
|---|---|---|---|
| `Healthy` | (no banner) | — | — |
| `Restarting` | yellow | `Kernel restarting (attempt N/3)` | `<reason> — automatic restart in progress (last exit at <ts>)` |
| `Halted (Clean)` | grey | `Kernel shut down cleanly at <ts>` | `Restart with raxis-supervisor start` (copy-able command) |
| `Halted (OperatorTerminated)` | grey | `Kernel terminated by operator at <ts>` | `Restart with raxis-supervisor start` (copy-able command) |
| `Halted (OperatorInterrupt)` | grey | `Kernel interrupted (Ctrl+C) at <ts>` | `Restart with raxis-supervisor start` (copy-able command) |
| `Halted (ExternalSigterm)` | grey | `Kernel terminated externally at <ts> (SIGTERM)` | `Supervisor not restarting per operator-signal contract. Restart with raxis-supervisor start` |
| `Halted (ExternalSigkill)` | grey | `Kernel terminated externally at <ts> (SIGKILL)` | `Supervisor not restarting per operator-signal contract. Restart with raxis-supervisor start` |
| `Halted (CircuitOpen)` | red | `Circuit breaker tripped after N crashes in 60 s` | `Manual intervention required: raxis-supervisor reset-circuit-breaker` (copy-able) |
| `Halted (sentinel-stale)` | amber | `Supervisor sentinel stale (last update <ts>)` | `Supervisor process may be wedged; check journal / launchd logs` |

WCAG-AA contrast for both light + dark modes (mirrors the `ChainStatusBanner` per-tone palette).

### §5.4 Polling cadence (`INV-DASHBOARD-KERNEL-LIFECYCLE-01`)

TanStack Query `useKernelLifecycle()` hook polls `/api/health/kernel-lifecycle` every `5 s`. The 5-second cadence is the upper-bound surfacing latency: if the sentinel transitions from `Healthy` → `Restarting`, the dashboard renders the new banner within 5 seconds.

---

## §6 — Migration + rollout plan

| Phase | Scope | Default | Live-e2e impact |
|---|---|---|---|
| Phase 1 (this PR) | All three tiers land behind `RAXIS_SUPERVISOR_AUTO_RESTART=1`. Default off. | Off | Zero — live-e2e doesn't set the env var; kernel exits as today on deadlock. |
| Phase 2 (post-working-e2e, separate PR) | Flip default-on for production deployments via launchd / systemd. Operator-signal contract is preconditional for OS-level service management. | On (production), Off (live-e2e + dev cargo test) | Live-e2e still opts out; production gets auto-restart. |
| Phase 3 (after 30 days observation) | Consider removing the opt-in gate entirely. | Always-on if observation shows zero false-restart loops. | Re-evaluated. |

---

## §7 — Relationship to the deferred `system-daemon` work

The `system-daemon` todo (launchd plist + systemd unit + `raxis daemon start/stop/status` CLI mentioned in `operator-ergonomics.md §...`) overlaps with this surface. Two integration paths are forward-compatible with both:

### Path A — Supervisor as the OS-supervised process

Launchd / systemd spawns `raxis-supervisor start`, which in turn spawns and supervises `raxis-kernel`. The OS-level supervisor restarts the supervisor binary itself if it crashes; the supervisor restarts the kernel binary if it exits non-zero.

* **Pros:** circuit breaker + sentinel + dashboard banner all keep working without any OS-level integration; operator gets the same restart-aware UI on macOS launchd as on Linux systemd.
* **Cons:** two-layer supervisor structure (OS supervises supervisor; supervisor supervises kernel); the OS-level restart of the supervisor is a rare event, but when it fires the in-memory circuit-breaker counter is rehydrated from `<data_dir>/supervisor_state.json` so operator intent persists.

### Path B — Kernel exits 70, OS supervisor restarts kernel directly

Launchd / systemd spawns `raxis-kernel` directly; the in-kernel deadlock detector exits with `70` and the OS-level supervisor restarts the kernel. The `raxis-supervisor` binary is not in the loop.

* **Pros:** simpler single-layer supervision; matches the original `concurrency-and-locking.md §7a` "panic = abort + supervisor restarts" model.
* **Cons:** no circuit breaker at the OS level (launchd's `KeepAlive` will infinite-restart; systemd needs explicit `Restart=on-failure StartLimitBurst=3 StartLimitIntervalSec=60`); no dashboard sentinel without adding an OS-level write hook; operator-signal contract has to be re-implemented per-OS (launchd vs systemd vs init).

**Recommendation:** **Path A** for production deployments. Path B is documented for operators who want the simpler topology and accept the per-OS configuration of the rate limit. The decision is deferred to the system-daemon PR; this PR ships only the supervisor binary (Path A's prerequisite) and explicitly leaves both the launchd plist and systemd unit out of scope.

---

## §8 — Test matrix (one row per witness)

| Invariant | Witness test | File |
|---|---|---|
| `INV-SUPERVISOR-RESTART-AUDIT-01` | spawn a kernel that exits 70 with a forensic dump, restart, verify next boot's audit chain has `KernelDeadlockDetected → KernelStarted → KernelRestartCompleted` and `verify-chain` is hash-clean | `raxis/kernel/tests/deadlock_supervisor_handoff.rs::deadlock_dump_rehydrates_into_audit_chain_and_chain_stays_clean` |
| `INV-SUPERVISOR-CIRCUIT-BREAKER-01` | spawn a fake child that exits 70 four times in 10 s; verify supervisor halts on attempt 4 with `CircuitOpen` sub-state and a `KernelRestartHaltedCircuitOpen` (synthesised on next boot if/when the operator clears) | `raxis/crates/supervisor/tests/circuit_breaker.rs::four_failures_in_window_open_circuit` |
| `INV-SUPERVISOR-OPT-IN-01` | invoke `raxis-supervisor start` without `RAXIS_SUPERVISOR_AUTO_RESTART=1`; verify supervisor logs the gate and exits 0 with no kernel child spawned | `raxis/crates/supervisor/tests/opt_in_gate.rs::no_env_var_means_no_supervision` |
| `INV-SUPERVISOR-SIGTERM-RESPECT-01` | spawn fake child, send SIGTERM to supervisor, verify supervisor forwards to child, child exits, supervisor exits 0 with sentinel `Halted (OperatorTerminated)` and NO replacement child spawned | `raxis/crates/supervisor/tests/sigterm_respect.rs::sigterm_to_supervisor_propagates_and_halts` |
| `INV-SUPERVISOR-SIGINT-RESPECT-01` | same shape with SIGINT; verify sentinel `Halted (OperatorInterrupt)` | `raxis/crates/supervisor/tests/sigint_respect.rs::sigint_to_supervisor_propagates_and_halts` |
| `INV-SUPERVISOR-EXIT-CODE-CLASSIFICATION-01` | one sub-test per row of the §4.4 table; assert `classify(outcome, intentional_shutdown) == expected_action` for each | `raxis/crates/supervisor/tests/exit_classification.rs::*` |
| `INV-SUPERVISOR-SHUTDOWN-GRACE-01` | spawn fake child that takes 5 s to exit on SIGTERM; supervisor with `RAXIS_SUPERVISOR_SHUTDOWN_GRACE_SECS=10` MUST NOT escalate to SIGKILL within those 5 s; assert child exited via SIGTERM (not SIGKILL) and sentinel reflects the operator-signal classification | `raxis/crates/supervisor/tests/shutdown_grace.rs::supervisor_waits_full_grace_before_sigkill` |
| `INV-DASHBOARD-KERNEL-LIFECYCLE-01` | write sentinel `Restarting (DeadlockDetected, attempt 1/3)`, mount `KernelLifecycleBanner`, assert it renders the yellow banner within 5 s; mutate sentinel to `Halted (CircuitOpen)`, assert it transitions to red within the next 5 s | `raxis/dashboard-fe/src/components/banners/__tests__/KernelLifecycleBanner.test.tsx` + `raxis/crates/dashboard/tests/kernel_lifecycle_endpoint.rs` |

---

## §9 — Where each guarantee lives

| Guarantee | File |
|---|---|
| Forensic-dump writer | `raxis/kernel/src/deadlock_dump.rs` |
| Watcher → exit 70 wiring | `raxis/kernel/src/main.rs::spawn_deadlock_watcher` |
| Boot-time dump rehydration | `raxis/kernel/src/main.rs` (between Step 6 and Step 7a) |
| New audit event variants | `raxis/crates/audit/src/event.rs::AuditEventKind` |
| Notification priority routing | `raxis/crates/dashboard-kernel/src/notification_filter.rs` |
| Supervisor binary | `raxis/crates/supervisor/src/main.rs` |
| Spawn-and-wait loop | `raxis/crates/supervisor/src/lib.rs::run` |
| Circuit breaker | `raxis/crates/supervisor/src/circuit_breaker.rs` |
| Sentinel writer | `raxis/crates/supervisor/src/sentinel.rs` |
| Exit-code classifier | `raxis/crates/supervisor/src/classify.rs` |
| Signal handler + grace | `raxis/crates/supervisor/src/signal.rs` |
| Dashboard sentinel handler | `raxis/crates/dashboard/src/routes/health.rs::kernel_lifecycle` |
| Dashboard React banner | `raxis/dashboard-fe/src/components/banners/KernelLifecycleBanner.tsx` |
| Operator recipe | `raxis/guides/operator/19-supervisor-and-restart.md` |
