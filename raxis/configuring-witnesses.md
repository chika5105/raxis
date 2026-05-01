# RAXIS — Configuring Witnesses

How an operator configures the witness system for a specific project. Witness configuration is the primary project-specific surface area in RAXIS: the kernel's gate enforcement logic is fixed, but the definition of what "passing a gate" means for each project is entirely operator-controlled.

---

## The Core Model

The kernel does not know what "a passing build" or "a passing test run" looks like for your project. It knows three things:

1. A gate type was required for this task (derived from the claim table in `policy.toml`)
2. A verifier process was spawned for that gate type
3. That verifier submitted a `WitnessSubmission` binding to the correct evaluation commit OID (`evaluation_sha` / task tip under review; verifier env `RAXIS_HEAD_COMMIT_SHA`) before its token expired

Everything in between — running Detox, running `cargo build`, doing cross-compilation — lives entirely in the verifier binary or script that the operator configures. The kernel is an evidence collector and gate enforcer, not a build system.

**What is fixed across all projects:**
- The IPC protocol between the verifier and kernel
- The `WitnessSubmission` message schema and SHA binding requirement
- The gate evaluation logic (did all required gate types pass for this task?)
- The cryptographic binding of witness to the evaluation commit OID (`evaluation_sha`) + `task_id`
- The audit trail format

**What varies per project (operator-configured):**
- Which gate types exist
- Which verifier command runs for each gate type
- Which file paths require which gate types (the claim table)

---

## Step 1 — Define Gate Types for Your Project

In `policy.toml`, declare one `[[gates]]` stanza per gate type. Each stanza names the gate, points to the verifier command, and sets a timeout.

### Example: lalapen (React Native mobile app)

```toml
[[gates]]
type         = "E2ETest"
command      = ["./scripts/verify-e2e.sh"]
working_dir  = "."
timeout_secs = 480
env          = { PLATFORM = "ios" }

[[gates]]
type         = "LintCheck"
command      = ["./scripts/verify-lint.sh"]
working_dir  = "."
timeout_secs = 120
```

### Example: Rust daemon (cross-OS)

```toml
[[gates]]
type         = "RustBuild_Linux"
command      = ["./scripts/verify-build-linux.sh"]
working_dir  = "."
timeout_secs = 600

[[gates]]
type         = "RustBuild_Windows"
command      = ["./scripts/verify-build-windows.sh"]
working_dir  = "."
timeout_secs = 900

[[gates]]
type         = "CrossCompile_AArch64"
command      = ["./scripts/verify-cross-aarch64.sh"]
working_dir  = "."
timeout_secs = 900
```

The kernel reads these stanzas from the signed policy artifact. These are the only verifiers it will ever spawn for this policy. A verifier not listed here cannot be submitted.

---

## Step 2 — Wire Gate Types to File Paths via the Claim Table

In the same `policy.toml`, the claim table maps path globs to required gate types. This is how the kernel determines which gates are required for a given task without asking the planner — it derives `touched_paths` from the VCS diff independently and evaluates each path against this table.

Rules are evaluated in declaration order; first match per path wins. The last rule should be a `**` catch-all.

### lalapen claim table

```toml
[[claim_rules]]
path_glob       = "e2e/**"
required_claims = ["E2ETest"]

[[claim_rules]]
path_glob       = "src/**/*.ts"
required_claims = ["E2ETest", "LintCheck"]

[[claim_rules]]
path_glob       = "**"
required_claims = ["LintCheck"]    # catch-all; any file not matched above requires lint
```

### Example claim table (multi-crate Rust service)

```toml
[[claim_rules]]
path_glob       = "daemon/src/core/topology/discover/windows/**"
required_claims = ["RustBuild_Windows", "CrossCompile_AArch64"]

[[claim_rules]]
path_glob       = "daemon/src/**/*.rs"
required_claims = ["RustBuild_Linux", "RustBuild_Windows"]

[[claim_rules]]
path_glob       = "api-server/src/**/*.rs"
required_claims = ["RustBuild_Linux"]

[[claim_rules]]
path_glob       = "**"
required_claims = ["RustBuild_Linux"]    # StrictDefault
```

**Important:** The planner has no say in which claims are required for a given task. The kernel computes `touched_paths` from the VCS diff, walks each path through this table, unions the results, and that is the required gate set. A planner-supplied path manifest is discarded.

---

## Step 3 — Write the Verifier Script or Binary

The verifier is a process spawned by the kernel. At spawn time, the kernel passes the following environment variables:

| Variable | Contents |
|---|---|
| `RAXIS_VERIFIER_TOKEN` | The `verifier_run_token` — single-use IPC authentication credential |
| `RAXIS_VERIFIER_RUN_ID` | UUID for this specific verifier run |
| `RAXIS_TASK_ID` | UUID for the task this gate belongs to |
| `RAXIS_HEAD_COMMIT_SHA` | The commit SHA the kernel is evaluating |
| `RAXIS_GATE_TYPE` | The gate type string (e.g., `RustBuild_Linux`) |
| `RAXIS_SOCKET` | Filesystem path to the kernel's IPC socket |

The verifier's contract:
1. Run the actual verification work
2. Connect to `$RAXIS_SOCKET`
3. Authenticate with `$RAXIS_VERIFIER_TOKEN`
4. Submit `WitnessSubmission { verifier_run_id, task_id, gate_type, head_commit_sha: <evaluation OID>, result }` (`head_commit_sha` field name is IPC-stable; value must match kernel `evaluation_sha` for the task)
5. Exit

The `raxis-witness-submit` CLI binary (from `raxis-verifier-sdk`) handles the IPC framing and authentication. Operators call it from their scripts rather than writing raw IPC code.

### Example — Linux build gate (Rust workspace)

```bash
#!/usr/bin/env bash
set -euo pipefail

# Run the actual work
cargo build --workspace 2>&1
BUILD_EXIT=$?

RESULT="Pass"
[ $BUILD_EXIT -ne 0 ] && RESULT="Fail"

raxis-witness-submit \
  --socket  "$RAXIS_SOCKET" \
  --token   "$RAXIS_VERIFIER_TOKEN" \
  --run-id  "$RAXIS_VERIFIER_RUN_ID" \
  --task-id "$RAXIS_TASK_ID" \
  --gate    "$RAXIS_GATE_TYPE" \
  --sha     "$RAXIS_HEAD_COMMIT_SHA" \
  --result  "$RESULT"

exit $BUILD_EXIT
```

### lalapen — E2E test gate

```bash
#!/usr/bin/env bash
set -euo pipefail

# Run the Detox E2E suite
npx detox test --configuration ios.sim.debug 2>&1
TEST_EXIT=$?

RESULT="Pass"
[ $TEST_EXIT -ne 0 ] && RESULT="Fail"

raxis-witness-submit \
  --socket  "$RAXIS_SOCKET" \
  --token   "$RAXIS_VERIFIER_TOKEN" \
  --run-id  "$RAXIS_VERIFIER_RUN_ID" \
  --task-id "$RAXIS_TASK_ID" \
  --gate    "$RAXIS_GATE_TYPE" \
  --sha     "$RAXIS_HEAD_COMMIT_SHA" \
  --result  "$RESULT"

exit $TEST_EXIT
```

The script logic is entirely project-specific. The RAXIS contract is: submit a typed witness before the verifier token expires. What runs in between is up to the operator.

---

## Step 4 — Cross-Compilation and Multi-Platform Witnesses

For projects requiring multiple platform targets (for example a cross-platform Rust service), write separate verifier scripts for each platform gate. The kernel spawns them independently and tracks them as distinct `verifier_run_id`s. **All required gates must pass** before the task's gate state clears — if `RustBuild_Linux` passes but `RustBuild_Windows` times out, the task stays `GatesPending` with `BlockReason::WitnessTimeout` on the Windows gate.

### Example — Windows cross-compilation gate

```bash
#!/usr/bin/env bash
set -euo pipefail

# Cross-compile for Windows from a Linux host using the cross toolchain
cross build --target x86_64-pc-windows-gnu --workspace 2>&1
BUILD_EXIT=$?

RESULT="Pass"
[ $BUILD_EXIT -ne 0 ] && RESULT="Fail"

raxis-witness-submit \
  --socket  "$RAXIS_SOCKET" \
  --token   "$RAXIS_VERIFIER_TOKEN" \
  --run-id  "$RAXIS_VERIFIER_RUN_ID" \
  --task-id "$RAXIS_TASK_ID" \
  --gate    "$RAXIS_GATE_TYPE" \
  --sha     "$RAXIS_HEAD_COMMIT_SHA" \
  --result  "$RESULT"

exit $BUILD_EXIT
```

### Example — AArch64 cross-compilation gate

```bash
#!/usr/bin/env bash
set -euo pipefail

cross build --target aarch64-unknown-linux-gnu --workspace 2>&1
BUILD_EXIT=$?

RESULT="Pass"
[ $BUILD_EXIT -ne 0 ] && RESULT="Fail"

raxis-witness-submit \
  --socket  "$RAXIS_SOCKET" \
  --token   "$RAXIS_VERIFIER_TOKEN" \
  --run-id  "$RAXIS_VERIFIER_RUN_ID" \
  --task-id "$RAXIS_TASK_ID" \
  --gate    "$RAXIS_GATE_TYPE" \
  --sha     "$RAXIS_HEAD_COMMIT_SHA" \
  --result  "$RESULT"

exit $BUILD_EXIT
```

All three verifiers run concurrently after a single `IntentRequest`. The planner receives `Admitted { gates_pending: [RustBuild_Linux, RustBuild_Windows, CrossCompile_AArch64] }` and polls until all three clear.

---

## Step 5 — Sign and Deploy the Policy

After finalizing `policy.toml` with gate definitions and claim rules:

```bash
# Sign the policy artifact with the operator's private key
raxis-cli policy sign ./policy.toml \
  --key ~/.raxis/keys/operator.pem

# Advance the policy epoch; all active delegations become stale (operator UDS; kernel must be running)
raxis-cli epoch advance
```

The epoch advances, all active delegations are marked stale, and the new gate configuration is live. Any planner session holding a delegation issued under the previous epoch must renew before the next gated action.

**Operator tokens issued under the old epoch are now invalid.** If an operator approved an escalation at epoch N and the epoch has advanced to N+1 before the token is presented, the token is rejected at step 2 of `validate_approval_token` (`EpochMismatch`). The operator must re-approve under the new epoch.

---

## What Varies Per Project, What Stays Constant

| Surface | lalapen | Rust multi-crate | Fixed by kernel |
|---|---|---|---|
| Gate types | `E2ETest`, `LintCheck` | `RustBuild_Linux`, `RustBuild_Windows`, `CrossCompile_AArch64` | — |
| Verifier commands | Detox scripts | `cargo build`, `cross build` scripts | — |
| Claim rules | `src/**/*.ts → E2ETest` | `daemon/src/**/*.rs → both builds` | — |
| Number of gates per task | 1–2 | 1–3 | — |
| `WitnessSubmission` format | Identical | Identical | ✓ |
| SHA binding (INV-03) | Identical | Identical | ✓ |
| Kernel gate evaluation logic | Identical | Identical | ✓ |
| Audit trail format | Identical | Identical | ✓ |
| Token TTL enforcement | Identical | Identical | ✓ |

The claim table, gate definitions, and verifier scripts are the per-project surface area. The IPC protocol, witness binding, gate evaluation logic, and audit trail are fixed by the kernel regardless of project.

---

## Verifier Failure Modes

| Failure | What the kernel sees | What the planner sees |
|---|---|---|
| Verifier exits before submitting witness | Token TTL expires → `WitnessTimeout` | `FAIL_MISSING_WITNESS` on re-poll |
| Verifier submits `WitnessResult::Fail` | Witness recorded; gate fails; task → `Aborted { WitnessFailure }` | `FAIL_MISSING_WITNESS` on re-poll |
| Verifier presents wrong commit OID (mismatch vs kernel `evaluation_sha`) | SHA mismatch (INV-03); witness rejected | `FAIL_MISSING_WITNESS` on re-poll |
| Verifier run ID not recognised | Token invalid; witness rejected | `FAIL_MISSING_WITNESS` on re-poll |
| Verifier submits witness for wrong gate type | Gate type mismatch; witness rejected | `FAIL_MISSING_WITNESS` on re-poll |

All failure modes surface to the planner as `FAIL_MISSING_WITNESS` — the coarse code is the same regardless of why a gate did not clear. The full detail (which failure mode, which verifier, which SHA mismatch) is in the audit log for operator investigation.

The agent diagnoses failures from its own workspace — the build output, the test runner's output, or the CI logs — not from anything the kernel relays back. This is intentional: the kernel's job is to say "this gate did not clear," not to relay verifier internals into the agent's context.
