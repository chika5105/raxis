# iter62 verifier-runtime — live-e2e wiring (D10)

This spec documents the live-e2e harness wiring that exercises the
V2 production verifier runtime end-to-end. It pairs with the
iter62 deliverables D1–D9 (image-bake plumbing + production
`raxis-verifier` crate + canonical-images digest pinning + `VerifierVm*`
audit family + reserved aliases) and is the wire-shape contract the
parent merge folds into the existing extended-e2e harness when
the file-ownership boundaries clear.

## Goal

The harness MUST observe the same image-bake / digest-verify /
VM-spawn path that production uses. No mocks, no stubs (the
test-only `verifier-stub` lives elsewhere; the harness must spawn
the real `raxis-verifier` binary baked into one of the two iter62
verifier images).

## Plan-side wiring — additive `[[tasks.verifiers]]` block

The realistic-scenario plan
(`live-e2e/examples/plan_primary.toml`) gains an additive
`[[tasks.verifiers]]` block on at least one Executor task. The
canonical iter62 wiring exercises the kernel-canonical
`raxis-verifier-symbol-index` image so the harness covers both
the digest-pinning path and the D7 fast-incremental built-in
pipeline:

```toml
# Append on any [[tasks]] block whose worktree the harness already
# materialises with at least a base + evaluation commit pair (the
# `materialize-records` Executor task is the simplest target).

[[tasks.verifiers]]
name        = "symbol_index"
image       = "raxis-verifier-symbol-index"
# When RAXIS_VERIFIER_BUILTIN is set the verifier bypasses
# `sh -lc <command>` and runs the in-process pipeline. The
# command field is still required by the schema; the verifier
# echoes it into the audit summary as `<builtin>` if the env
# var is set.
command     = ["true"]
timeout_ms  = 30_000
on_failure  = "warn_only"
artifact    = "/raxis/symbol_index.json"

  [tasks.verifiers.env]
  # iter62 D7: activate the in-process symbol-index pipeline.
  RAXIS_VERIFIER_BUILTIN       = "symbol-index"
  # The kernel mounts `/raxis/base_index/symbol_index.json` at
  # spawn time (cf. `crates/verifier/src/lib.rs::run_builtin_symbol_index`).
  RAXIS_BASE_SYMBOL_INDEX_PATH = "/raxis/base_index/symbol_index.json"
  # Cap the parallel ctags fan-out so the harness behaviour is
  # deterministic across CI hardware shapes.
  RAXIS_VERIFIER_PARALLELISM   = "4"
```

(`RAXIS_BASE_SHA` and `RAXIS_EVALUATION_SHA` are populated by the
kernel's spawn envelope automatically — operator policy does NOT
declare them.)

## Policy-side wiring

The harness's `enable_gateway_in_policy` helper (the same one the
witness-verifier worker already touched in
`kernel/tests/extended_e2e_concurrent_lifecycle.rs`) gains an
additive `[[gates]]` line at the END of the function so the
verifier-symbol-index gate is admissible:

```rust
// Append at the END of `enable_gateway_in_policy`, after the
// existing gate declarations:
policy_toml.push_str(
    "\n[[gates]]\n\
     gate_type           = \"symbol_index\"\n\
     verifier_command    = \"/usr/bin/raxis-verifier\"\n\
     max_wall_seconds    = 30\n\
     max_memory_bytes    = 268435456\n",
);
```

No new policy struct fields are needed — this uses the existing
operator-side `[[gates]]` schema.

## Audit-chain assertion

After the verifier exits, the harness MUST observe the following
event sequence for the same `verifier_run_id` correlation key:

1. `VerifierVmSpawned { image_alias = "raxis-verifier-symbol-index", ... }`
2. `VerifierVmExited  { signal_class = "exit", exit_code = Some(0), ... }`
3. `VerifierWitnessReceived { verdict = "Pass", artifact_sha256 = Some(...), artifact_bytes = Some(...) }`

Any other shape — `VerifierTimeout`, `VerifierImageDigestMismatch`,
or `VerifierArtifactRejected` — fails the assertion. The harness
already has helpers for audit-chain traversal; the additive code is
the three `assert_eq!` calls keyed off
`AuditEventKind::Verifier*::as_str()`.

The paired-write contract from `INV-VERIFIER-AUDIT-PAIRED-WRITE-01`
(D11) makes this assertion structurally complete: every spawn must
either (a) pair with both `VerifierVmExited` AND
`VerifierWitnessReceived` (the happy path the assertion above
covers), or (b) short-circuit to one of `VerifierTimeout`,
`VerifierImageDigestMismatch`, or `VerifierArtifactRejected`. The
harness fails fast on the short-circuit shapes because the
realistic scenario seeds a worktree the verifier can complete in
under the 30-second timeout budget.

## File-ownership boundaries

`kernel/tests/extended_e2e_support/*` is Worker 4 territory; this
spec deliberately documents the wiring rather than landing the
edits directly. The parent's merge pass is the right point to
fold the additive block into whichever extended-e2e suite is in
the right state at merge time.

The `live-e2e/examples/plan_primary.toml` edit is a single
additive `[[tasks.verifiers]]` block at the END of an existing
`[[tasks]]` block — string-edit-only, no restructuring of
existing blocks. iter62 ships that one edit directly so the
example seed already exercises the production verifier path
even before the parent's full harness wiring lands.

## Bake-step prerequisites

Every prerequisite is already documented:

* `cargo xtask images bake-all` (run by the parent at merge time)
  populates the `RAXIS_EXPECTED_VERIFIER_*_IMAGE_DIGEST_HEX` envs
  the canonical-images build script reads. Until the bake step
  runs, every spawn of the symbol-index verifier surfaces
  `VerifierImageDigestMismatch` because the embedded digest is
  the all-zero placeholder — the kernel-canonical posture stays
  loud.

* The `raxis-verifier` binary (`crates/verifier`) is baked into
  both `images/verifier-starter/` and
  `images/verifier-symbol-index/` overlays per the iter62 D4 + D5
  `Containerfile` shapes.

* The `raxis-verifier-symbol-index` alias is reserved by
  `RESERVED_SYMBOL_INDEX_VM_IMAGE_NAME`; operator
  `[[vm_images]]` rules that try to claim it are rejected with
  `FAIL_POLICY_RESERVED_VM_IMAGE_NAME` (`INV-VERIFIER-12`).
