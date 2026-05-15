# Worker 4 (iter62 keep-alive flag) — return notes

## No kernel-side changes required

The keep-alive flag is implemented entirely inside Worker 4's
file-ownership boundary
(`kernel/tests/**`, `live-e2e/**`, `specs/**`). No `kernel/src/`
changes were needed, and no parent-side action is required for
the kernel binary itself.

## Pre-existing compose-teardown callsite audit

The parent's iter62 clarification asked Worker 4 to find every
`docker compose down` / `docker compose stop` / `docker compose
rm` invocation in the test harness and gate it behind the new
keep-alive helper. Audit result: **the live-e2e harness today
contains zero compose-teardown invocations**.

The realism-e2e harness (`extended_e2e_realistic_scenario.rs`)
brings the compose-backed stack UP via
`extended_e2e_support::docker_stack::ensure_extended_stack_up_or_panic`
(`docker compose ... up -d --wait`) but never tears it down —
the operator runs `cargo xtask observability down -- -v` (or
`docker compose -p raxis-live-e2e-test -f
live-e2e/docker-compose.extended.e2e.yml down -v`) by hand
after the test finishes. The worker therefore added a
forward-compatible RAII guard
(`extended_e2e_support::docker_stack::ComposeStackGuard`)
whose `Drop` honours the keep-alive opt-out for any FUTURE
caller that wants the harness itself to issue `docker compose
down`. The default `teardown_on_drop = false` preserves
current "leave the stack up" behaviour; the witness pair
`compose_stack_drop_runs_teardown_when_no_keep_alive_signal`
+ `compose_stack_drop_skips_down_when_keep_running` pins the
keep-alive composition.

The live-e2e harness's `inv_grafana_datasource_provisioned_at_stack_up_01.sh`
shell script DOES run `docker compose down -v` under its
`--bounce` flag, but that script is operator-invoked manually
and is not called by the test harness during normal runs, so
it is out of scope for the keep-alive flag.

## Known limitation: kernel survival past `cargo test` exit

When `cargo test` exits, the kernel daemon's `Stdio::piped()`
stderr pipe loses its read end (the test process owned it).
The kernel's next stderr write may receive `SIGPIPE` and
terminate the daemon, even with all teardown calls skipped.

**Workaround** (documented in `specs/v3/live-e2e-keep-alive.md
§3.3`): operators who want true post-`cargo test`-exit
survival run the test under `setsid` / `nohup`, OR keep the
test process alive in the foreground (the keep-alive flag is
designed for inspection during a single operator session, not
for background daemonisation).

A more robust fix — redirecting kernel `stdout` / `stderr`
directly to `<data_dir>/kernel.stderr.log` via `Stdio::from(file)`
at spawn time — was scoped out of this commit because it
changes the contract of `KernelInstance::wait_for_ready` (which
greps in-memory `stderr_lines` populated by the pipe-reader
thread). If the parent wants this hardening it can be done in
a follow-up by also changing `wait_for_ready` to poll the
on-disk file.
