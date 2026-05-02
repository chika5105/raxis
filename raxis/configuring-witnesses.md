# RAXIS — Configuring Witnesses

How an operator configures the witness system for a specific project. Witness configuration is the primary project-specific surface area in RAXIS: the kernel's gate enforcement logic is fixed, but the definition of what "passing a gate" means for each project is entirely operator-controlled.

**Normative contracts:** Gate definitions and verifier env vars follow [`specs/v1/kernel-store.md`](specs/v1/kernel-store.md) §2.5.6. Claim path rules follow the signed policy artifact schema in [`specs/v1/philosophy.md`](specs/v1/philosophy.md) (see `[claim_requirements]`). Wire format for witness IPC is [`specs/v1/peripherals.md`](specs/v1/peripherals.md) §3.3.

---

## The Core Model

The kernel does not know what "a passing build" or "a passing test run" looks like for your project. It knows three things:

1. Which claim types apply to the task (derived from `claim_requirements` in the signed `policy.toml`, using kernel-computed `touched_paths` — see INV-07)
2. A verifier process was spawned for each required gate type (per `[[gates]]` in the same artifact)
3. That verifier submitted a `WitnessSubmission` binding to the correct evaluation commit OID (`evaluation_sha`, supplied to the verifier as env var **`RAXIS_EVALUATION_SHA`**) before its token expired

Everything in between — running Detox, running `cargo build`, doing cross-compilation — lives entirely in the verifier binary or script that the operator configures. The kernel is an evidence collector and gate enforcer, not a build system.

**What is fixed across all projects:**
- The IPC protocol between the verifier and kernel
- The `WitnessSubmission` message schema and SHA binding requirement
- The gate evaluation logic (did all required gate types pass for this task?)
- The cryptographic binding of witness to the evaluation commit OID (`evaluation_sha`) + `task_id`
- The audit trail format

**What varies per project (operator-configured):**
- Which gate types exist (`[[gates]]`)
- Which verifier command runs for each gate type
- Which file paths require which claim types (`[[claim_requirements.rules]]`)

---

## Step 1 — Define Gate Types for Your Project

In `policy.toml`, declare one `[[gates]]` stanza per gate type. Field names and types are normative in [`kernel-store.md`](specs/v1/kernel-store.md) §2.5.6 (`gate_type`, `verifier_command`, `max_wall_seconds`, `max_memory_bytes`, `network_allowed`).

### Example: lalapen (React Native mobile app)

```toml
[[gates]]
gate_type        = "TestCoverage"
verifier_command = "/usr/local/bin/raxis-verify-e2e.sh"
max_wall_seconds = 480
max_memory_bytes = 2147483648
network_allowed  = false

[[gates]]
gate_type        = "LintClean"
verifier_command = "/usr/local/bin/raxis-verify-lint.sh"
max_wall_seconds = 120
max_memory_bytes = 536870912
network_allowed  = false
```

### Example: Rust daemon (cross-OS)

Normative field names only — **`gate_type`** strings must match `GateType` variants in `raxis-types` for your kernel build (see [`philosophy.md`](specs/v1/philosophy.md) workspace layout).

```toml
[[gates]]
gate_type        = "RustBuild_Linux"
verifier_command = "/usr/local/bin/raxis-verify-build-linux.sh"
max_wall_seconds = 600
max_memory_bytes = 2147483648
network_allowed  = false

[[gates]]
gate_type        = "RustBuild_Windows"
verifier_command = "/usr/local/bin/raxis-verify-build-windows.sh"
max_wall_seconds = 900
max_memory_bytes = 2147483648
network_allowed  = false

[[gates]]
gate_type        = "CrossCompile_AArch64"
verifier_command = "/usr/local/bin/raxis-verify-cross-aarch64.sh"
max_wall_seconds = 900
max_memory_bytes = 2147483648
network_allowed  = false
```

The kernel reads these stanzas from the signed policy artifact. These are the only verifiers it will ever spawn for this policy. A verifier not listed here cannot be submitted.

---

## Step 2 — Wire Claim Types to File Paths via `claim_requirements`

In the same `policy.toml`, **`[[claim_requirements.rules]]`** maps path globs to **`claims`** (claim types). This matches the schema in [`philosophy.md`](specs/v1/philosophy.md) §Policy Artifact — not `[[claim_rules]]` / `path_glob` / `required_claims` (those names are not v1).

The kernel derives `touched_paths` from the VCS diff independently and evaluates each path against this table (first matching rule per path, ordered list; union of claim types across paths).

Rules should be ordered **most specific first**; a catch-all `pattern = "**"` may appear last for documentation (unmatched paths still imply strict defaults per the loader — see philosophy).

Strings in **`claims`** are **`ClaimType`** values from your signed policy / `raxis-types` — they are **not** required to spell the same as **`gate_type`** in `[[gates]]`, though many deployments use parallel naming. Wire your policy so required claims map to the gates you defined (task-level gate stanzas in the signed **plan** may also apply — see [`fixtures/gated_plan.toml`](fixtures/gated_plan.toml)).

### lalapen claim requirements

```toml
[[claim_requirements.rules]]
pattern = "e2e/**"
claims  = ["StrictDefault"]

[[claim_requirements.rules]]
pattern = "src/**/*.ts"
claims  = ["StrictDefault", "SecurityReview"]

[[claim_requirements.rules]]
pattern = "**"
claims  = ["StrictDefault"]
```

### Example claim requirements (multi-crate Rust service)

```toml
[[claim_requirements.rules]]
pattern = "daemon/src/core/topology/discover/windows/**"
claims  = ["SecurityReview", "StrictDefault"]

[[claim_requirements.rules]]
pattern = "daemon/src/**/*.rs"
claims  = ["StrictDefault"]

[[claim_requirements.rules]]
pattern = "api-server/src/**/*.rs"
claims  = ["StrictDefault"]

[[claim_requirements.rules]]
pattern = "**"
claims  = ["StrictDefault"]
```

**Important:** The planner cannot influence which claims are required. The kernel computes `touched_paths` from the VCS diff, walks each path through this table, unions the results, and that is the required claim set. A planner-supplied path manifest is discarded (INV-07).

---

## Step 3 — Write the Verifier Script or Binary

The verifier is a process spawned by the kernel. At spawn time, the kernel passes **only** the environment variables in [`kernel-store.md`](specs/v1/kernel-store.md) §2.5.6 (`VerifierSpawnEnvelope`). The subprocess environment is cleared before `exec` — do not rely on inherited vars.

| Variable | Contents |
|---|---|
| `RAXIS_VERIFIER_TOKEN` | Single-use token for witness IPC authentication |
| `RAXIS_TASK_ID` | Task identifier for this gate run |
| `RAXIS_EVALUATION_SHA` | Commit OID the witness must bind (`evaluation_sha` in `WitnessSubmission`) |
| `RAXIS_WORKTREE_ROOT` | Planner session worktree (working directory for evaluation) |
| `RAXIS_KERNEL_SOCKET` | Absolute path to the kernel UDS for witness intake |
| `RAXIS_GATE_TYPE` | Gate type string (must match `gate_type` from `[[gates]]`) |
| `RAXIS_INITIATIVE_ID` | Initiative id (logging context only; not for auth decisions) |

The verifier's contract:

1. Run the verification work under `RAXIS_WORKTREE_ROOT` as needed.
2. Open `RAXIS_KERNEL_SOCKET` and send a single **`WitnessSubmission`** (length-prefixed **bincode** framing per [`peripherals.md`](specs/v1/peripherals.md) §3.3 — not JSON on the wire).
3. Include `evaluation_sha` equal to **`RAXIS_EVALUATION_SHA`**; mismatch → rejection (`EvaluationShaMismatch`).
4. Exit `0` after submission attempted (gate pass/fail is expressed by `result_class` in the payload, not only by exit code — see §2.5.6 exit-code table).

Below, placeholder comments stand in for your IPC client; implement using `raxis-ipc` types or an internal helper that matches Part 3.

### Example — Linux build gate (Rust workspace)

```bash
#!/usr/bin/env bash
set -euo pipefail

cd "$RAXIS_WORKTREE_ROOT"

# Run the build without `set -e` aborting on non-zero exit; capture the exit
# code so we can decide RESULT_CLASS. Without the `&&/||` guard, `set -e`
# would abort here on any build failure and the witness would never be
# submitted, leaving the kernel to mark the gate as WitnessTimeout instead
# of receiving a typed Fail witness.
cargo build --workspace 2>&1 && BUILD_EXIT=0 || BUILD_EXIT=$?

if [ "$BUILD_EXIT" -eq 0 ]; then
  RESULT_CLASS="Pass"
else
  RESULT_CLASS="Fail"
fi

# Submit WitnessSubmission { verifier_token, task_id, gate_type, evaluation_sha, result_class, body }
# over UDS $RAXIS_KERNEL_SOCKET — see specs/v1/peripherals.md §3.3
./tools/submit_witness.sh "$RESULT_CLASS"

# IMPORTANT: always exit 0 after a successful witness submission. The kernel
# reads gate Pass/Fail from the witness body (`result_class`); a non-zero
# verifier-process exit is a *separate* signal meaning "the verifier itself
# crashed before submitting a witness" (per specs/v1/kernel-store.md §2.5.6,
# verifier_run_tokens / witness_records semantics). Propagating $BUILD_EXIT
# here would conflate "build failed (legitimate Fail witness submitted)"
# with "verifier process crashed (no witness submitted)", causing the kernel
# to log spurious VerifierProcessFailure events on every legitimate Fail.
exit 0
```

### lalapen — E2E test gate

```bash
#!/usr/bin/env bash
set -euo pipefail

cd "$RAXIS_WORKTREE_ROOT"

# See "Linux build gate" above for the rationale behind the `&&/||` guard
# and the trailing `exit 0`.
npx detox test --configuration ios.sim.debug 2>&1 && TEST_EXIT=0 || TEST_EXIT=$?

if [ "$TEST_EXIT" -eq 0 ]; then
  RESULT_CLASS="Pass"
else
  RESULT_CLASS="Fail"
fi

./tools/submit_witness.sh "$RESULT_CLASS"

exit 0
```

The script logic is project-specific. The RAXIS contract is: submit a typed witness before the verifier token expires, with **`evaluation_sha`** matching **`RAXIS_EVALUATION_SHA`**.

---

## Step 4 — Cross-Compilation and Multi-Platform Witnesses

For projects requiring multiple platform targets (for example a cross-platform Rust service), configure separate `[[gates]]` entries and verifier scripts. The kernel spawns them independently; each run has its own **`verifier_run_id`** (assigned by the kernel — not passed as an env var in v1). **All required gates must pass** before the task can complete — if `RustBuild_Linux` passes but `RustBuild_Windows` times out, the task ends in **`Aborted`** with **`BlockReason::WitnessTimeout`** per the v1 FSM ([`philosophy.md`](specs/v1/philosophy.md) §1.3).

The planner learns completion and gate state through **`IntentResponse`** (`Accepted` / `Rejected`) and **`task_state`** ([`peripherals.md`](specs/v1/peripherals.md) §3.1), not through a separate `Admitted { gates_pending }` shape — see [`kernel-feedback-flows.md`](kernel-feedback-flows.md).

### Example — Windows cross-compilation gate

```bash
#!/usr/bin/env bash
set -euo pipefail

cd "$RAXIS_WORKTREE_ROOT"

# See "Linux build gate" above for the rationale behind the `&&/||` guard
# and the trailing `exit 0`.
cross build --target x86_64-pc-windows-gnu --workspace 2>&1 && BUILD_EXIT=0 || BUILD_EXIT=$?

if [ "$BUILD_EXIT" -eq 0 ]; then
  RESULT_CLASS="Pass"
else
  RESULT_CLASS="Fail"
fi

./tools/submit_witness.sh "$RESULT_CLASS"

exit 0
```

### Example — AArch64 cross-compilation gate

```bash
#!/usr/bin/env bash
set -euo pipefail

cd "$RAXIS_WORKTREE_ROOT"

# See "Linux build gate" above for the rationale behind the `&&/||` guard
# and the trailing `exit 0`.
cross build --target aarch64-unknown-linux-gnu --workspace 2>&1 && BUILD_EXIT=0 || BUILD_EXIT=$?

if [ "$BUILD_EXIT" -eq 0 ]; then
  RESULT_CLASS="Pass"
else
  RESULT_CLASS="Fail"
fi

./tools/submit_witness.sh "$RESULT_CLASS"

exit 0
```

---

## Step 5 — Sign and Deploy the Policy

After finalizing `policy.toml` with gate definitions and `claim_requirements`:

```bash
# Sign the policy artifact with the authority private key (policy artifacts are
# authority-signed; plan artifacts are operator-signed — see specs/v1/kernel-store.md §2.5.4)
raxis-cli policy sign ./policy.toml \
  --key ~/.raxis/keys/authority.pem \
  --out ~/.raxis/policy/policy.toml.next

# Advance the policy epoch; delegations become stale-on-next-use
# (operator UDS; kernel must be running). Both --policy and --sig are required —
# see specs/v1/cli-ceremony.md `epoch advance`.
raxis-cli epoch advance \
  --policy ~/.raxis/policy/policy.toml.next \
  --sig ~/.raxis/policy/policy.toml.next.sig
```

The epoch advances and the new gate configuration is live. Planner sessions with stale delegations must renew before the next gated action.

**Approval tokens issued under the old epoch are invalid** after advance: presentation yields **`EpochMismatch`** until the operator re-issues under the new epoch ([`philosophy.md`](specs/v1/philosophy.md) escalation test matrix).

---

## What Varies Per Project, What Stays Constant

| Surface | lalapen | Rust multi-crate | Fixed by kernel |
|---|---|---|---|
| Gate types | `TestCoverage`, `LintClean` | `RustBuild_Linux`, `RustBuild_Windows`, `CrossCompile_AArch64` | — |
| Verifier commands | Detox scripts | `cargo build`, `cross build` scripts | — |
| Claim rules | `pattern` / `claims` rows | same (`claim_requirements`) | — |
| Gates per task | 1–2 | 1–3 | — |
| `WitnessSubmission` format | Identical | Identical | ✓ |
| SHA binding (INV-03) | Identical | Identical | ✓ |
| Kernel gate evaluation | Identical | Identical | ✓ |
| Audit trail format | Identical | Identical | ✓ |
| Token TTL enforcement | Identical | Identical | ✓ |

---

## Verifier Failure Modes

Planner-facing codes are coarse ([`planner-api.md`](specs/v1/planner-api.md), INV-08). Typical mappings:

| Failure | What the kernel does | What the planner tends to see |
|---|---|---|
| Verifier exits before submitting witness | Token TTL → timeout handling; task may **`Aborted`** (`WitnessTimeout`) | **`FAIL_TASK_NOT_RUNNING`** / **`FAIL_UNKNOWN_TASK`** once aborted, or **`FAIL_MISSING_WITNESS`** while still waiting on an intent path |
| Verifier submits `result_class: Fail` | Witness recorded; gate does not clear | **`FAIL_INSUFFICIENT_WITNESS`** on a later intent such as **`CompleteTask`** ([`planner-api.md`](specs/v1/planner-api.md)) |
| Wrong OID vs `RAXIS_EVALUATION_SHA` | Witness rejected (`EvaluationShaMismatch`) | **`FAIL_MISSING_WITNESS`** or stuck gates until a matching witness is submitted |
| Invalid / consumed verifier token | Witness rejected | Same coarse family as above |

Exact codes depend on handler branch and task state; operators use the **audit log** for precise causes. The agent is expected to diagnose build/test output from its own worktree, not from verifier internals relayed by the kernel.
