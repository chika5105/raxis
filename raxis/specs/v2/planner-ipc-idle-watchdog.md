# Planner IPC idle watchdog

> Normative reference for `INV-PLANNER-IPC-IDLE-WATCHDOG-01`.

## 1. Failure mode addressed

A substrate-spawned planner VM (orchestrator / executor / reviewer)
can become *wedged*: the host-side hypervisor still reports the VM
as running, the kernel still holds the matching
`Box<dyn IsolationSession>` handle, but no IPC frame ever arrives on
the planner socket. Without external intervention the kernel's
dispatch loop blocks on `read_frame(&mut stream).await` forever,
consuming an admission slot and silently breaking every DAG that
depends on this task.

### 1.1 Empirically observed root cause (iter71/iter72)

The first reproducer in the wild was the **AVF orphan XPC**
pathology on macOS:

1. The kernel daemon is killed with `SIGKILL` (operator runs
   `pkill -9 raxis-kernel`, CI runner times out, etc.). `SIGKILL`
   is uncatchable; no `Drop` impl runs.
2. `Apple Virtualization.framework` parents every `VZVirtualMachine`
   it spawns onto `launchd` (PID 1) via `XPCService`. When the
   parent kernel process dies, the AVF XPC service is **not** torn
   down — it stays running as a `launchd`-rooted orphan,
   indistinguishable from a live VM at `ps` time.
3. The orphan retains its vsock CID, virtiofs daemon handle, and
   guest console-log file descriptor.
4. The next kernel start spawns fresh VMs. AVF assigns them fresh
   CIDs, but the *guest-side* `vsock_loopback_bridge` /
   `airgap_a3_chokepoint` initialisation races against the
   leftover virtiofs daemons and console writers from the orphans.
5. The resulting fresh VM boots far enough to log
   `planner-boot` on its console, then wedges before its first
   `IntentRequest`. The kernel never observes another frame.

The symptom matches at the kernel: `planner_session_revoked_on_exit`
never logs, `intent_response` never logs for these sessions, and
the operator sees the DAG stuck at `Running` state for tasks whose
VMs are observably still consuming admission units.

### 1.2 Class of failures the watchdog generalises over

The orphan pathology is the *instigator*, but the watchdog covers
every fault that manifests as **"the kernel observes no frame from
this planner for an extended window"**, including:

* In-guest PID 1 panic that does not propagate (rare; the planner
  driver's `shutdown_or_exit` path usually catches this).
* Guest-kernel deadlock (e.g. kernel lock contention in the
  microVM kernel).
* Host-side vsock fd starvation (the substrate's queue is full and
  AVF stops scheduling reads).
* Model-gateway hang propagating into the in-guest planner driver
  (the planner stops issuing intents while it waits for a fetch
  response that will never arrive).
* Future substrate-level faults whose taxonomy is not yet known.

The watchdog is *intentionally* class-agnostic. It does not try to
diagnose the root cause; it observes the **absence of progress**
over time and forces a recovery transition.

## 2. Wire contract

### 2.1 Timer

Each iteration of `drive_planner_stream`'s frame-read loop wraps
its `read_frame(&mut stream)` call in `tokio::time::timeout(threshold, …)`.

The threshold is read once per `drive_planner_stream` invocation
from `RAXIS_PLANNER_IPC_IDLE_TIMEOUT_SECS` (per-process env var)
with a default of **900 seconds**. Setting the env var to `0`
disables the watchdog entirely (long-running stress tests opt out
this way).

### 2.2 Fired-flag propagation

When the timer elapses the loop:

1. Emits a structured stderr breadcrumb:

   ```json
   {"level":"warn","event":"planner_ipc_idle_watchdog_fired",
    "session_id":"<sid>","idle_threshold_secs":<n>}
   ```

2. Sets `idle_watchdog_fired = true` on the returned
   `PlannerStreamOutcome`.
3. Breaks out of the dispatch loop with a normal `Ok(outcome)`.

### 2.3 Substrate teardown

Before the SQL revoke runs, `spawn_planner_dispatcher` checks the
flag and — when true — calls
`SessionSpawnService::terminate_session(session_id, 5s_grace)`.
This issues the substrate's `shutdown_grace_then_force` dance,
which:

* On AVF: `VZVirtualMachine.stop(...)` plus a forced escalation
  inside the 5s grace window. The host-side XPC process is reaped;
  the vsock CID and virtiofs handle are released.
* On Firecracker: the firecracker process is sent `SIGTERM` then
  `SIGKILL` if it doesn't exit gracefully.

The `terminate_session` call also emits the canonical
`SessionVmExited` audit event (with `signal_class = "ForceKilled"`
or equivalent backend-specific reason), so the chain stays
internally consistent.

### 2.4 Failure-reason synthesis

The Mode-B post-exit synthesiser in
`session_spawn_orchestrator::spawn_planner_dispatcher` consumes the
flag via the new `idle_watchdog: Option<IdleWatchdogFired>`
parameter on `build_worker_post_exit_failure_reason`. The
watchdog branch **pre-empts every other source-of-truth tier** —
exit notice, dispatch error, and activity breadcrumb are all by
definition stale when the planner stopped emitting frames before
they could observe a new event.

The synthesised `tasks.block_reason` names the watchdog firing,
the threshold, and the last observed intent (when any) so the
operator can correlate against `planner_ipc_idle_watchdog_fired`
in `kernel.stderr.log` without consulting the kernel configuration.

## 3. Why per-frame, not per-session

A naive "session has been alive for too long" timer would not
distinguish between a 30-minute productive turn (e.g. a slow
LLM call followed by a long bash compile) and a 30-minute stall.
The per-frame timer correctly drops to zero on every observed
frame — IntentRequest, WitnessSubmission, EscalationRequest,
*and* `PlannerExitNotice` all reset the deadline. The only thing
that elapses the timer is true IPC silence.

The threshold default of 900s sits comfortably above the
worst-case **single-frame interval** the system can produce:

| Source | Worst-case interval |
| --- | --- |
| Gateway round-trip (Anthropic / OpenAI big prompt) | ~120s |
| In-VM bash budget cap (kernel-mediated egress chokepoint) | ~90s |
| Long-running compile / test in workspace | ~300s |
| Slack between a tool result and the next LLM turn | ~5s |

15 minutes covers the sum of the worst cases with ~6x headroom.
A genuine stall hits the threshold in one window; no false
positive class has been identified.

## 4. Detection improvements layered on top

The watchdog is the **recovery** mechanism. Two complementary
**prevention** mechanisms attack the AVF orphan root cause
directly:

### 4.1 Test-harness orphan reaper

The `live-e2e` extended scenarios now scan for
`com.apple.Virtualization.VirtualMachine.xpc` processes at the
start of each run and refuse to bootstrap until they are gone. This
prevents the orphan-from-prior-test pathology from polluting a
fresh kernel start.

Operators can opt into the same reaper for production kernel
restarts via `RAXIS_BOOT_REAP_AVF_ORPHANS=1`. The default in
production is **off** because a poorly-tuned policy could
delete VMs from a parallel non-Raxis Virtualization-framework
consumer.

### 4.2 Test-harness fail-fast logging

When the test harness sees an `idle_watchdog_fired` breadcrumb in
the kernel stderr stream, it surfaces the matching session_id +
threshold + last-seen intent through the test failure report,
giving the operator a one-line diagnosis instead of a 30-minute
"the test never finished" wait.

## 5. Behavioural witnesses

### 5.1 Unit tests

* `kernel/src/session_spawn_orchestrator.rs` →
  `concrete_reason_idle_watchdog_pre_empts_other_tiers` —
  asserts the watchdog branch wins over every other tier.
* `kernel/src/session_spawn_orchestrator.rs` →
  `concrete_reason_idle_watchdog_with_activity` — asserts the
  watchdog reason inlines the last-observed intent for
  forensic correlation.

### 5.2 Integration test (deferred — `xfail` recovery slot)

`kernel/tests/idle_watchdog_recovery.rs` (TODO):

1. Spawn a fake substrate that returns a `Box<dyn IsolationSession>`
   whose `recv()` never resolves.
2. Run `drive_planner_stream` against it with `RAXIS_PLANNER_IPC_IDLE_TIMEOUT_SECS=2`.
3. Assert the function returns within ~3 seconds with
   `idle_watchdog_fired = true`.
4. Assert the post-exit hook calls `terminate_session` (the fake
   substrate records the call).
5. Assert the task transitions `Running → Failed` with a
   `block_reason` containing the watchdog signature.

## 6. Invariant declaration

> **`INV-PLANNER-IPC-IDLE-WATCHDOG-01`** — Every
> kernel-supervised planner-IPC dispatch loop MUST bound the
> wall-clock time between consecutive IPC frames from the planner.
> When the bound is exceeded the kernel MUST forcibly terminate
> the substrate session (via `SessionSpawnService::terminate_session`)
> AND synthesise a CONCRETE Mode-B failure reason that names the
> watchdog firing AND the threshold. The synthesised reason MUST
> pre-empt every other source-of-truth tier (structured exit
> notice, dispatch-stream error, activity breadcrumb) because
> every other tier is by definition stale when the watchdog
> fires.

## 7. Cross-references

* `kernel/src/ipc/server.rs` — `drive_planner_stream` watchdog
  arm + `PlannerStreamOutcome::idle_watchdog_fired` +
  `planner_ipc_idle_timeout`.
* `kernel/src/session_spawn_orchestrator.rs` —
  `spawn_planner_dispatcher` post-exit `terminate_session` call
  + `build_worker_post_exit_failure_reason` watchdog branch.
* `specs/v2/audit-paired-writes.md §4` — `SessionVmExited` audit
  event emitted by `terminate_session` (no change required;
  watchdog routes through the existing emit site).
* `specs/invariants.md` — `INV-PLANNER-IPC-IDLE-WATCHDOG-01`
  declaration.
* `specs/v2/planner-harness.md §14` — boundary contract for
  planner-side IPC frame cadence (consumed by the watchdog
  threshold default).
