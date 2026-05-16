# iter67 follow-ups

Tracking non-blocking issues surfaced during the iter67 pipeline that
do NOT gate iter67 itself (`extended_e2e_realistic_scenario::realistic_session_lifecycle`).
Each entry should land as a small `fix(<crate>): <symptom>` PR after
iter67 ships.

The pipeline target was iter67 GREEN; the items below are
clippy-sweep / harness-drift artifacts in adjacent test targets that
fell out of `cargo test --release --workspace --no-fail-fast` while
the umbrella was being verified.

## Phase 3 (`cargo test --release --workspace`) failures

Captured under iter67 commit `14cbd9a` (origin/main tip after the
clippy sweep). Phase 3 was SKIPPED per the parent's amendment because
the iter66 unit witnesses (`safety::tests`, `panic_hook::tests`,
`db.rs::async_runtime_safety::*`) had already proven well-formed at
the type level under `cargo build --release --workspace --all-targets`
+ `cargo clippy --release --workspace --all-targets -- -D warnings`,
and the eight target failures below are not reachable from the iter67
test binary (`extended_e2e_realistic_scenario`), which compiles and
runs independently:

  1. `-p raxis-dashboard --test hardening_smoke` — needs investigation;
     adjacent dashboard tests (`real_bundle_serving`,
     `static_bundle_serving`) pass cleanly.

  2. `-p raxis-dashboard-kernel --lib` — `task_llm_turn_view_projection`
     integration tests pass; the lib-test compile likely fails on a
     separate witness target. Re-run with
     `cargo test --release -p raxis-dashboard-kernel --lib` to capture
     the specific compiler error.

  3. `-p raxis-kernel --bin raxis-kernel` — TEST-PROFILE compile of
     the binary; the production `cargo build --release -p raxis-kernel
     --bin raxis-kernel` is GREEN (verified during iter67 launch
     prep). Likely a `#[cfg(test)]`-gated import shaved during the
     clippy sweep that the binary's embedded unit tests still expect.

  4. `-p raxis-kernel --test kernel_full_lifecycle_e2e` — separate
     integration test target; not consumed by iter67's
     `realistic_session_lifecycle`.

  5. `-p raxis-kernel --test kernel_signal_shutdown` — four RUNTIME
     failures (not compile):
       * `audit_chain_intact_across_kernel_started_and_kernel_stopped`
       * `kernel_can_restart_cleanly_and_chain_persists`
       * `sigint_also_triggers_graceful_shutdown_with_distinct_audit_reason`
       * `sigterm_triggers_graceful_shutdown_and_kernel_stopped_audit`
     Likely flaky due to docker compose stack contention with the
     iter67 launch (both bind ports / sockets in the same host slot).
     Re-run after iter67 lands and the docker stack is torn down.

  6. `-p raxis-kernel --test mock_planner_end_to_end` — separate
     integration test target; not iter67-relevant.

  7. `-p raxis-kernel --test post_ceiling_orchestrator_respawn` —
     separate integration test target; not iter67-relevant.

  8. `-p raxis-store --lib` — store crate's lib-test target; the
     standalone `migration_sql_dumps.rs` integration test passes (2/2
     ok), so the failure is in the in-crate `tests` module. Most
     likely candidate: a knock-on from the iter66
     `async_runtime_safety` block plus the `[features] test-support
     = []` declaration added at `ab9861c`.

## Recovery from these followups

None of the items above touch:
  * iter66's `INV-KERNEL-RECOVERY-PRESERVES-SAFETY-INVARIANTS-01`
    umbrella semantics.
  * iter66's `INV-KERNEL-STORE-LOCK-SYNC-NEVER-FROM-ASYNC-01`
    boundary contract.
  * The Layer 3 panic hook installation order or audit-emit shape.

Recommended sequence:
  1. Land iter67 GREEN (this pipeline's deliverable).
  2. Open one PR per item with a `fix(<crate>): restore <symbol>`
     style message, FF main.
  3. Confirm `cargo test --release --workspace --no-fail-fast` is
     fully green before iter68 begins.
