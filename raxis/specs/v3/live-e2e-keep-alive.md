# RAXIS V3 — Live-E2E Keep-Alive Flag

> **Status:** Implemented (operator post-mortem ergonomics; dev-only)
>
> **Cross-references:**
> - `specs/invariants.md` — `INV-E2E-KEEP-ALIVE-DEFAULT-OFF-01` (the keep-running flag MUST default to off; absent any signal, all teardown paths execute as before).
> - `specs/v2/e2e-extended-scenario.md` — realism-e2e harness whose teardown surface this spec gates.
> - graceful shutdown SIGTERM step the keep-alive flag conditionally skips.
> - `kernel/tests/common/keep_alive.rs` — single source of truth for the activation read.
> - `kernel/tests/extended_e2e_support/docker_stack.rs::ComposeStackGuard` — Drop-side guard that wires the flag through compose-stack teardown.

---

## 1. The problem

When the live-e2e realism scenario exits — success, failure, or timeout — the test harness tears everything down:

- The kernel daemon is `SIGTERM`'d (`kernel.shutdown_with(libc::SIGTERM, …)` at the bottom of `realistic_session_lifecycle`).
- The `KernelInstance::Drop` safety net `SIGKILL`s the kernel if shutdown didn't complete.
- The `OtelPusherSupervisor::Drop` `SIGTERM`-then-`SIGKILL`s the `raxis-otel-pusher` sidecar.
- The `Tier3Reporter::Drop`, when `RAXIS_E2E_KEEP=0` AND the test succeeded, `remove_dir_all`s `<data_dir>` (kernel.db, audit chain, kernel.stderr.log, sockets, worktrees — all gone).
- The kernel-managed AVF (macOS) / Firecracker (Linux) guest VMs die with the kernel.

Once the test process exits the operator has the cargo log capture and nothing else. The dashboard URL is stale — the kernel is gone. The audit chain is gone. The SQLite db is gone. There is nothing to inspect.

**This makes post-mortem inspection of a real failure ~impossible.** A live-e2e iteration produces a wealth of forensic state — operator dashboard panels, the SQLite tasks/intents tables, the JSONL audit segments, the per-task LLM raw turns, the kernel's own structured-event stderr — and it all evaporates between "test fails" and "operator opens a browser tab".

V3 specifies an opt-in keep-alive flag that, when set, tells the harness to skip every teardown so the operator can inspect the running services at leisure and tear them down by hand when finished.

---

## 2. Activation surfaces (any one signal activates)

The flag is read from three control surfaces. **Any one being "on" activates keep-alive**; the default (no signal) leaves behavior identical to pre-keep-alive (`INV-E2E-KEEP-ALIVE-DEFAULT-OFF-01`).

### 2.1 Env var (primary)

```bash
export RAXIS_INSTALL_DIR="${RAXIS_INSTALL_DIR:-/usr/local/lib/raxis}"
RAXIS_LIVE_E2E=1 RAXIS_LIVE_E2E_REALISTIC=1 \
RAXIS_E2E_KEEP_RUNNING_AFTER_EXIT=1 cargo test --release \
    -p raxis-kernel --test extended_e2e_realistic_scenario -- --nocapture
```

The older short spelling remains accepted for operator runbooks that
already use it:

```bash
export RAXIS_INSTALL_DIR="${RAXIS_INSTALL_DIR:-/usr/local/lib/raxis}"
RAXIS_LIVE_E2E=1 RAXIS_LIVE_E2E_REALISTIC=1 \
RAXIS_KEEP_ALIVE=1 RAXIS_KEEP_ALIVE_DURATION_SECS=7200 cargo test --release \
    -p raxis-kernel --test extended_e2e_realistic_scenario -- --nocapture
```

| Value (case-insensitive)                     | Activates? |
| --------------------------------------------- | ---------- |
| `1`, `true`, `yes`, `on`                      | yes        |
| `0`, `false`, `no`, `off`, empty, unset       | no         |
| Anything else (`garbage`, `maybe`, …)         | no         |

Truthy parsing is intentionally lenient on the positive side (a copy-paste from a CI yaml's `KEEP_RUNNING: "true"` JustWorks); conservative on the negative side (a typo'd value never accidentally keeps services running).

### 2.2 Touch file (workdir-anchored, mid-run)

`<work_dir>/KEEP_RUNNING` (any byte content; existence is the signal) flips the flag from another shell after the test has already started:

```bash
# In another terminal, while the realism-e2e test is mid-run:
touch /tmp/raxis-realism-e2e-iter62/KEEP_RUNNING
```

This is the "I just realised something interesting is happening, don't tear it down" affordance. The `<work_dir>` is the kernel's data directory (the path the harness logs as `[realism-e2e] kernel data dir : …`).

### 2.3 CLI flag (`--keep-running-after-exit`)

For test binaries that take args. The current `cargo test`-driven binaries do not parse argv; the env var is the canonical surface. The CLI bit is exposed via `keep_alive::set_cli_flag(true)` for any future caller.

### 2.4 Precedence

OR — any one signal activates. None of them dominate the others; a future maintainer who flipped this to AND would trip the `keep_running_after_exit_cli_flag_activates` and `keep_running_after_exit_touch_file_activates` witnesses.

### 2.5 Post-run hold duration

When keep-alive is active, the harness keeps its own process alive
after success or failure so the kernel dashboard, stderr reader, and
sidecars remain connected for inspection. The default hold is 7200
seconds. Override it with:

```bash
RAXIS_E2E_KEEP_ALIVE_DURATION_SECS=1800
```

The short alias `RAXIS_KEEP_ALIVE_DURATION_SECS` is accepted too.
`0` skips the sleep while still skipping teardown. Values above one
day are clamped to 86400 seconds.

---

## 3. What stays running, what tears down

### 3.1 Stays running (when the flag is on)

- `raxis-kernel` daemon. The operator dashboard at `http://127.0.0.1:<dashboard_port>` (default `19820`, override via `RAXIS_E2E_DASHBOARD_PORT`) stays mounted.
- `raxis-otel-pusher` sidecar. Live metrics keep flowing to OTLP `http://127.0.0.1:4318` and Prometheus keeps `up{job=~"raxis.*"} = 1`.
- The docker-compose backing stack (postgres + mongo + redis + smtp + mysql + mssql + Grafana + Prometheus + OTel collector). The harness today never auto-tears this down anyway, but the keep-alive guard makes the guarantee explicit (see §4).
- Kernel-managed AVF / Firecracker guest VMs that were mid-task at the moment the test reached teardown.
- `<work_dir>` (`<data_dir>`): kernel.db, audit chain, kernel.stderr.log, worktrees, sockets — all preserved on disk.

### 3.2 Tears down regardless

- The test harness's own state machine. Assertions still fire, the test still panics on a failed witness, the verdict still propagates to `cargo test`'s exit code. Keep-alive only affects cleanup, **not pass/fail signaling** — the test exits with its actual verdict code.

### 3.3 What this flag does NOT guarantee

- **Unbounded daemonisation after the hold window.** Keep-alive is a bounded
  post-mortem hold, not a process supervisor. Once the hold duration
  elapses, `cargo test` exits with the real verdict and any orphaned
  child process survival is best-effort. Production deployments use
  launchd / systemd / ECS instead.
- **Compose-stack survival across host reboots.** The compose stack uses named volumes (`{project}_prometheus_data`, `{project}_grafana_data`) that survive `docker compose down` but not host reboots if the volumes are wiped externally.

---

## 4. Docker compose stack

The realism-e2e harness brings the compose-backed stack UP via `extended_e2e_support::docker_stack::ensure_extended_stack_up_or_panic` (which routes through `docker compose -p raxis-live-e2e-test -f live-e2e/docker-compose.extended.e2e.yml up -d --wait`). Today's harness **never tears that stack down** — the operator runs `cargo xtask observability down -- -v` (or `docker compose -p raxis-live-e2e-test -f live-e2e/docker-compose.extended.e2e.yml down -v`) by hand after the test finishes.

The `ComposeStackGuard` RAII type in `kernel/tests/extended_e2e_support/docker_stack.rs` is the **forward-compatible Drop site** for any future caller that wants the harness to issue `docker compose down` itself. The guard composes the keep-alive opt-out with an explicit `teardown_on_drop` toggle:

| `teardown_on_drop` | Keep-alive flag | Drop behaviour                              |
| ------------------ | --------------- | ------------------------------------------- |
| `false` (default)  | (any)           | no-op (current harness behaviour preserved) |
| `true`             | off             | runs `docker compose down -v` (default-on)  |
| `true`             | on              | skipped (operator inspects compose stack)   |

The default-on "teardown runs when the flag is off" branch is pinned by `compose_stack_drop_runs_teardown_when_no_keep_alive_signal`. The "teardown skipped under keep-alive" branch is pinned by `compose_stack_drop_skips_down_when_keep_running`. Both witnesses live alongside `ComposeStackGuard` in `docker_stack.rs::tests`.

### 4.1 Manual teardown commands

The keep-alive banner the harness prints at end-of-test surfaces the canonical teardown commands (the harness's banner threads the `(project, compose_file)` pair into the block; the snippet below is what the realism-e2e harness emits):

```text
============================================================
RAXIS E2E KEEP-ALIVE: services left running for post-mortem
============================================================
  Dashboard      http://127.0.0.1:19820
  Grafana        http://127.0.0.1:3000
  Prometheus     http://127.0.0.1:9090
  OTel HTTP      http://127.0.0.1:4318
  Kernel stderr  tail -f <work_dir>/kernel.stderr.log
  SQLite         sqlite3 <work_dir>/kernel.db
  Audit chain    cat <work_dir>/audit/segment-000.jsonl
  Work-dir       <work_dir>
  Compose stack  docker compose -p raxis-live-e2e-test \
                   -f live-e2e/docker-compose.extended.e2e.yml ps

To tear down:
  pkill -f raxis-kernel; pkill -f extended_e2e_realistic_scenario; \
    pkill -f otelcol; pkill -f prometheus; pkill -f grafana-server
  rm -rf <work_dir>

To tear down compose:
  docker compose -p raxis-live-e2e-test \
    -f live-e2e/docker-compose.extended.e2e.yml down -v
============================================================
```

For the simpler `full_e2e_session_lifecycle` driver (which does not import the realism-extended `docker_stack` module), the banner falls back to a generic compose hint pointing at `cargo xtask observability ps / down -v`.

---

## 5. Wiring sites

The keep-alive flag is read at every site where the harness would otherwise issue a teardown:

| Site                                                            | File                                                                       | Default behaviour                                                                                    | Keep-alive behaviour |
| --------------------------------------------------------------- | -------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- | -------------------- |
| `kernel.shutdown_with(SIGTERM, …)` + post-mortem chain walk     | `kernel/tests/extended_e2e_realistic_scenario.rs`, `full_e2e_session_lifecycle.rs` | sends SIGTERM, asserts kernel exits cleanly, walks audit chain                                       | skipped, banner printed instead |
| `PostRunKeepAliveGuard::Drop`                                   | `kernel/tests/common/keep_alive.rs`                                    | no-op                                                                                               | prints the post-mortem banner and sleeps for the configured hold duration |
| `KernelInstance::Drop`                                          | `kernel/tests/common/kernel_harness.rs`                                    | SIGKILLs kernel if still alive (panic-path safety net)                                               | skipped              |
| `OtelPusherSupervisor::Drop`                                    | `kernel/tests/extended_e2e_support/otel_pusher.rs`                         | SIGTERM-then-SIGKILL the pusher (500 ms grace)                                                       | skipped (child forgotten so no destructor fires) |
| `Tier3Reporter::Drop` cleanup branch                            | `kernel/tests/common/tier3_artifacts.rs`                                   | `remove_dir_all(<data_dir>)` when `RAXIS_E2E_KEEP=0` AND success                                     | skipped, log line announces "keep-running flag active; RAXIS_E2E_KEEP=0 ignored" |
| `ComposeStackGuard::Drop`                                       | `kernel/tests/extended_e2e_support/docker_stack.rs`                        | `docker compose down -v` when `teardown_on_drop = true` (no caller enables this today)               | skipped              |

Every site reads the flag through the single helper `keep_alive::keep_running_after_exit_with_workdir(Some(work_dir))` so the contract has one source of truth. A future cleanup site (e.g. a `BrowserGuard` that closes a Cursor / Chrome tab) plugs into the same helper.

---

## 6. Witness coverage

Pinned in `kernel/tests/common/keep_alive.rs::tests` and `kernel/tests/extended_e2e_support/docker_stack.rs::tests`:

| Witness                                                   | Pins                                                                         |
| --------------------------------------------------------- | ---------------------------------------------------------------------------- |
| `keep_running_after_exit_default_is_false`                | `INV-E2E-KEEP-ALIVE-DEFAULT-OFF-01` — absent any signal, helper returns false |
| `keep_running_after_exit_env_var_activates`               | every truthy/falsy spelling of the env var                                    |
| `keep_running_after_exit_short_alias_activates`            | `RAXIS_KEEP_ALIVE=1` activates the same keep-alive path                         |
| `keep_alive_duration_secs_uses_canonical_then_alias_then_default` | duration env precedence, default, and one-day clamp                         |
| `post_run_keep_alive_guard_drop_respects_zero_duration`    | post-run guard is safe to run from Drop and respects `duration=0`              |
| `parse_truthy_env_value_canonical_cases`                  | pure parser, every truthy/falsy spelling                                     |
| `keep_running_after_exit_touch_file_activates`            | `<work_dir>/KEEP_RUNNING` activation                                          |
| `keep_running_after_exit_cli_flag_activates`              | CLI bit OR'd with env / touch                                                |
| `cli_flag_name_pinned`                                    | `--keep-running-after-exit` / env / touch-file spellings                      |
| `harness_drop_skips_teardown_when_keep_running`           | mock harness Drop: every signal flips the gate; default branch tears down    |
| `print_keep_alive_banner_never_panics`                    | banner emission MUST NOT panic on any reasonable input                        |
| `compose_stack_drop_runs_teardown_when_no_keep_alive_signal` | `INV-E2E-KEEP-ALIVE-DEFAULT-OFF-01` (compose arm) — default-on teardown       |
| `compose_stack_drop_skips_down_when_keep_running`         | every signal gates the `ComposeStackGuard` Drop's `docker compose down`       |
| `compose_stack_guard_default_teardown_disabled`           | constructor default `teardown_on_drop = false` (preserves current behaviour)  |
| `compose_stack_guard_for_extended_stack_constants_pinned` | `(COMPOSE_PROJECT, extended_compose_file())` pinned for the realism-e2e flow  |

---

## 7. Why dev-only

This is an **operator post-mortem affordance for a test harness**. It explicitly leaves long-lived processes around without supervision and is **not** a production posture. A production deployment runs the kernel under launchd / systemd / ECS, never under a test binary.

The flag exists for one reason: an operator running `cargo test ... extended_e2e_realistic_scenario` who hits a failure should not have to re-run the whole 30-minute live-e2e iter just to look at the dashboard. The dashboard, the SQLite db, the audit chain, and the docker-compose stack are sitting in front of them; the keep-alive flag stops the harness from hiding them.

---

## 8. Summary of operator commands

```bash
# Run the realism-e2e iter and keep everything live for post-mortem.
export RAXIS_INSTALL_DIR="${RAXIS_INSTALL_DIR:-/usr/local/lib/raxis}"
RAXIS_LIVE_E2E=1 RAXIS_LIVE_E2E_REALISTIC=1 \
RAXIS_E2E_KEEP_RUNNING_AFTER_EXIT=1 cargo test --release \
    -p raxis-kernel --test extended_e2e_realistic_scenario -- --nocapture

# Older short spelling accepted by the harness too:
export RAXIS_INSTALL_DIR="${RAXIS_INSTALL_DIR:-/usr/local/lib/raxis}"
RAXIS_LIVE_E2E=1 RAXIS_LIVE_E2E_REALISTIC=1 \
RAXIS_KEEP_ALIVE=1 RAXIS_KEEP_ALIVE_DURATION_SECS=7200 cargo test --release \
    -p raxis-kernel --test extended_e2e_realistic_scenario -- --nocapture

# Mid-run (in another shell), flip the flag without restarting:
touch <work_dir>/KEEP_RUNNING

# After inspection, tear down by hand:
pkill -f raxis-kernel
pkill -f extended_e2e_realistic_scenario
pkill -f raxis-otel-pusher
docker compose -p raxis-live-e2e-test \
    -f live-e2e/docker-compose.extended.e2e.yml down -v
rm -rf <work_dir>
```
