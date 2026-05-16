# iter62 verifier-runtime — return note to parent

This branch ships the V2 production verifier runtime per the iter62
deliverable list (D1–D13). Most of the work is self-contained inside
the `worker/iter62-verifier-runtime` file-ownership boundary; the
items below name the cross-cutting follow-ups the parent must fold
in at merge time.

## D8 — VerifierVm* audit emission wiring

The new `AuditEventKind::Verifier*` family lands in
`crates/audit/src/event.rs` (variants + `as_str` arms + witness
tests), the `KNOWN_AUDIT_EVENT_KINDS` allowlist + drift-guard
probes are extended in `crates/policy/src/bundle.rs`, and the
dashboard SSE bridge (`bridge_kind_if_relevant` in
`kernel/src/notifications/sink.rs`) accepts every variant. The
emission helpers themselves live in the new
`kernel/src/gates/verifier_audit.rs` module, with stable wire-string
constants for `signal_class` (`exit` / `signal` / `timeout` /
`killed`) and `reason` (`size_cap` / `path_escape` / `sha_mismatch`)
plus a unit suite that pins the paired-write cardinality from
`INV-VERIFIER-AUDIT-PAIRED-WRITE-01`.

What the parent needs to wire at merge time:

* **`kernel/src/gates/verifier_runner.rs::spawn_verifier`** — call
  `verifier_audit::emit_vm_spawned(audit_sink, &VerifierAuditContext { ... })`
  immediately after Step 5 (the `ACTIVE_VERIFIERS.fetch_add(1, ...)`
  line) on the success path. The watcher tokio task should call
  `emit_vm_exited` on the normal-wait arm of its `select!` and
  `emit_timeout` on the timeout arm. Threading the audit sink in
  requires extending the `spawn_verifier` signature; doing it here
  is parent-territory because the witness handler (parent-owned)
  also calls `spawn_verifier`.

* **`kernel/src/handlers/witness.rs::handle`** (parent-owned) —
  call `verifier_audit::emit_witness_received` once the witness is
  admitted, and `verifier_audit::emit_artifact_rejected` on the
  artefact admission gate's reject paths (size cap, path-escape,
  sha mismatch). The `verifier_run_id` is already in scope here
  (it is the witness submission's correlation key).

* **Spawn preflight** — wherever the kernel's
  `verify_canonical_image_via_manifest` is invoked for the two
  iter62 verifier images, call
  `verifier_audit::emit_image_digest_mismatch` on the
  `DigestMismatch` arm. The most common emit site is going to be
  the spawn preflight in `kernel/src/canonical_images_preflight.rs`.

The helper functions are `pub fn` and take `&dyn AuditSink` plus
the per-event correlation keys, so the wiring is mechanical — no
new design decisions remain.

## D10 — live-e2e wiring

The Worker-4-owned `kernel/tests/extended_e2e_support/*` plan
builders are too invasive for this branch to touch directly (we
would collide with whatever Worker 4 has in flight). The additive
plan-snippet the live-e2e harness should exercise is documented in
`raxis/specs/v2/iter62-verifier-runtime-live-e2e.md` (NEW —
parent's call whether to fold it into one of the existing live-e2e
specs or keep it standalone). The key block is:

```toml
[[plan.tasks.exec_a.verifiers]]
image      = "raxis-verifier-symbol-index"
name       = "symbol_index"
command    = "true"           # ignored — built-in path activates via env
on_failure = "warn_only"
artifact   = "/raxis/symbol_index.json"

[plan.tasks.exec_a.verifiers.env]
RAXIS_VERIFIER_BUILTIN          = "symbol-index"
RAXIS_BASE_SHA                  = "<base sha from harness>"
RAXIS_BASE_SYMBOL_INDEX_PATH    = "/raxis/base_index/symbol_index.json"
```

The audit-chain assertion the harness must run after the verifier
exits:

* exactly one `VerifierVmSpawned` with `image_alias =
  "raxis-verifier-symbol-index"`
* exactly one `VerifierWitnessReceived` with `verdict = "Pass"`
  (matching the same `verifier_run_id`)

If the parent prefers to ship the test inside an existing
extended-e2e harness, the additive policy edit is a one-line
`[[gates]]` block at the END of the existing
`enable_gateway_in_policy` helper — string-edit only, no
restructuring.

## D7 — symbol-index built-in pipeline

The pipeline ships in `crates/verifier/src/symbol_index.rs`
(module) + `crates/verifier/src/lib.rs` (`run_builtin_symbol_index`
orchestration). Activated by setting `RAXIS_VERIFIER_BUILTIN =
"symbol-index"` in the spawn envelope; bypasses
`sh -lc $RAXIS_VERIFIER_COMMAND` and runs the diff-scoped /
content-addressed / parallel-ctags pipeline directly.

Per the iter62 process constraints, the actual `cargo xtask images
bake-all` invocation (which populates the
`RAXIS_EXPECTED_VERIFIER_*_IMAGE_DIGEST_HEX` envs the canonical-
images build script reads) is parent-territory. Until the bake
step runs, the kernel-canonical posture stays loud — every spawn
of the symbol-index verifier surfaces
`VerifierImageDigestMismatch` because the embedded digest is the
all-zero placeholder.

## D9 — reserved alias

`RESERVED_GENERAL_VERIFIER_VM_IMAGE_NAME = "raxis-verifier-starter"`
lands in `crates/policy/src/bundle.rs` + `lib.rs` re-export, and
the `validate_vm_images` rejection arm refuses operator
`[[vm_images]] name = "raxis-verifier-starter"` with
`FAIL_POLICY_RESERVED_VM_IMAGE_NAME`. No further wiring needed;
the dashboard's policy-load-failure renderer already keys off the
`FAIL_POLICY_*` family.

## File-ownership reminder

This branch deliberately did NOT touch:

* `kernel/src/handlers/witness.rs` (parent)
* `kernel/src/scheduler/dag.rs` (parent)
* `kernel/src/initiatives/lifecycle.rs` (parent)
* `kernel/src/ipc/operator.rs` (parent)
* `crates/observability/*` (Worker 1)
* `crates/session-spawn/src/lib.rs` (Worker 1)
* `crates/store/migrations/*` (Worker 1)
* `crates/planner-core/src/dispatch.rs` / `driver.rs` (Worker 2)
* `dashboard-fe/**` (Worker 3)
* `kernel/tests/full_e2e_session_lifecycle.rs` and the other
  Worker-4 e2e harnesses (Worker 4)
* `crates/verifier-stub/**` (kept AS-IS for the kernel-internal
  test surface)

All shared-file edits (audit-event enum, policy bundle, sink
bridge, invariants) were append-only inside clearly-bounded
`// === iter62 verifier-runtime: ... ===` sections.

## Open questions for the parent

* **KsbSnapshot collisions** — none observed; the verifier runtime
  does not touch the KSB seam.
* **CI-runbook step** — once the bake step populates the digests,
  add the `RAXIS_EXPECTED_VERIFIER_STARTER_IMAGE_DIGEST_HEX` and
  `RAXIS_EXPECTED_VERIFIER_SYMBOL_INDEX_IMAGE_DIGEST_HEX` env vars
  to the release-pipeline secrets / build-script invocation chain
  alongside the existing Reviewer / Orchestrator equivalents.
