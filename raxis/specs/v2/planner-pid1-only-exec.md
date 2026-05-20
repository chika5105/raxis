# Planner binary PID-1-only execution

> Normative reference for `INV-PLANNER-PID1-ONLY-EXEC-01`.

## 1. Failure mode addressed

The three planner binaries — `raxis-executor`,
`raxis-orchestrator`, `raxis-reviewer` — are wired as the `/init`
of a Linux microVM (PID 1). After PID 1 boots, the binary remains
on disk at `/usr/local/bin/raxis-{executor,orchestrator,reviewer}`,
reachable through `$PATH` from the agent's bash tool.

In iter72 forensics we observed the executor's Claude agent
invoking `bash -lc "raxis-executor --help"` while diagnosing a
`dep-fetch-evidence` DNS failure. The agent had no malicious
intent — it was exploring the environment in a debugging spiral
— but a *child invocation* of the executor binary **inside its
own VM** IS a jailbreak vector:

1. The child inherits the parent PID 1's environment, including
   `RAXIS_PLANNER_TASK_PROMPT_PATH` and
   `RAXIS_KERNEL_VSOCK_LISTEN_PORT`. The child can collide with
   the parent's kernel-side planner IPC setup until the parent's
   session is revoked.
2. The child can read the parent's `/proc/<parent_pid>/cmdline`
   to learn the parent's per-task arguments (initiative id, task
   id) and impersonate the parent's identity at the kernel-side
   dispatch matrix.
3. The child's port-binding attempts (vsock loopback forwarder
   on the credential-proxy port; airgap-A3 chokepoint on port
   3129) collide with the parent's, which manifests at the
   host as a stalled VM — exactly the kind of stall the iter72
   idle watchdog catches **after** the damage is done.

The class of risk is **agent-driven privilege escalation**: an
LLM whose prompt has been (intentionally or accidentally) steered
toward `raxis-executor` reuses the parent's authority to perform
actions the parent had no intent to perform.

## 2. Defense

`raxis-planner-core::guest_init::enforce_pid1_or_abort` is invoked
as **Step 0** of every planner binary's `main()`, before any
filesystem or env hydration. On Linux it:

* `std::process::id() == 1` → return `Ok(())`. Normal flow.
* `std::process::id() != 1` + bypass unset → emit a structured
  stderr breadcrumb (`planner_pid1_enforcement_violation`) with
  `pid`, `ppid`, `argv0`, and the cited invariant; call
  `std::process::exit(126)`. The exit code is distinct from
  every documented planner exit so an operator scanning `dmesg`
  or substrate logs can tell at a glance that the binary
  refused to start because of a re-exec attempt.
* `std::process::id() != 1` + bypass set → emit a structured
  stderr warning (`planner_pid1_enforcement_bypassed`) and
  return. The bypass exists only for the host-mode
  `SubprocessIsolation` test fixture (which spawns planner
  binaries as ordinary child processes in legacy kernel tests).

On non-Linux platforms the helper is a no-op: the planner binaries
cross-compile to aarch64-linux and never execute natively on macOS
or Windows hosts.

### 2.1 Bypass surface

The `RAXIS_PLANNER_PID1_ENFORCEMENT_BYPASS=1` env var bypasses the
check. It is set automatically by
`raxis_test_support::SubprocessIsolation::spawn` for every child
it spawns. Production microVM substrates (Firecracker, AVF) MUST
NOT set the bypass — they spawn planner binaries directly as `/init`
(PID 1) so the check naturally returns `Ok(())`.

### 2.2 Compounding defenses (future)

The PID-1 guard alone is **sufficient** for the LLM-curious case.
For an adversarial agent that disables the guard by
`unset`ting environment hints, the following layered defenses are
already in place (witnessed by other invariants):

* Session token rotation on every planner exit
  (`INV-PLANNER-CLEAN-COMPLETION-MUST-NOT-WRAP-REJECTED-INTENT-01`)
  bounds the window during which a stolen token is valid.
* Kernel-side `INV-KERNEL-STATELESS-VM-CONCURRENCY-CAP-01`
  refuses additional concurrent sessions from the same token
  beyond cap.
* The idle watchdog
  (`INV-PLANNER-IPC-IDLE-WATCHDOG-01`) catches the wedged-VM
  signature when port-binding collisions stall the parent.

Future hardening — tracked but not yet wired — could include:

* `chmod 0500` the planner binary at PID-1 startup so only PID 1
  (root) can execute it. Adds a second line of defense without
  affecting normal operation.
* `unlink(2)` the binary's on-disk path after PID 1 boot. The
  kernel keeps the exec'd image in memory; the agent cannot
  recover the deleted bytes through `/proc/self/exe` because
  that's owned by PID 1.

These are intentionally deferred: the PID-1 guard delivers the
operator-visible signal (a distinct exit code + structured
breadcrumb) needed for incident response, and the compounding
defenses can land independently without breaking the guard's
contract.

## 3. Behavioural witnesses

### 3.1 Unit tests

* `crates/planner-core/src/guest_init.rs` →
  `pid1_enforcement_tests::pid1_enforcement_exit_code_is_126` —
  pins the operator-facing exit code.
* `crates/planner-core/src/guest_init.rs` →
  `pid1_enforcement_tests::enforce_pid1_or_abort_is_noop_on_non_linux` —
  pins the macOS / Windows no-op contract (test runners pass).
* `crates/planner-core/src/guest_init.rs` →
  `pid1_enforcement_tests::enforce_pid1_or_abort_respects_bypass_outside_pid1` —
  pins the SubprocessIsolation bypass contract (Linux only).

### 3.2 Integration evidence

A future Linux-target regression test (in
`live-e2e/tests/pid1_guard_blocks_inguest_reexec.rs`) would
exercise the full positive path: bake an executor image, boot a
session, have a fake "agent" exec `/usr/local/bin/raxis-executor`
inside the VM, and assert the child exits with code 126 and the
breadcrumb appears in the VM console log. This is left out of
the initial commit because the live-e2e harness already covers
the spawn surface for production microVMs.

## 4. Invariant declaration

> **`INV-PLANNER-PID1-ONLY-EXEC-01`** — Each planner binary
> (`raxis-executor`, `raxis-orchestrator`, `raxis-reviewer`)
> MUST refuse to start on Linux when its PID is not 1, except
> when explicitly bypassed via
> `RAXIS_PLANNER_PID1_ENFORCEMENT_BYPASS=1` (host-mode
> SubprocessIsolation test fixtures only). The refusal MUST
> produce a structured stderr breadcrumb naming the violation
> AND exit with code 126 (distinct from every documented
> planner exit). The check MUST run BEFORE any filesystem
> mount, env hydration, or socket binding so a child invocation
> cannot perform any of the parent's privileged setup steps.

## 5. Cross-references

* `crates/planner-core/src/guest_init.rs` —
  `enforce_pid1_or_abort` + `PID1_ENFORCEMENT_EXIT_CODE`.
* `crates/planner-{executor,orchestrator,reviewer}/src/main.rs` —
  Step 0 invocation site.
* `crates/test-support/src/subprocess_isolation.rs` —
  automatic bypass for the host-mode test fixture.
* `specs/v2/planner-ipc-idle-watchdog.md` — companion
  failure-mode taxonomy (iter71/iter72).
* `specs/invariants.md §INV-PLANNER-PID1-ONLY-EXEC-01` —
  invariant declaration.
