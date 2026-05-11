# Verifier env vars (`RAXIS_VERIFIER_TOKEN` & friends)

> **Topic:** Environment variables | **Time to read:** ~3 min | **Complexity:** ⭐⭐⭐ Advanced

When the kernel spawns a verifier subprocess, it stamps a fixed
set of env vars into the verifier's environment. The verifier
binary reads them, runs its check, then sends a `WitnessSubmission`
back to the kernel over `RAXIS_KERNEL_SOCKET`. This recipe is the
reference for those env vars — useful when you're authoring a
custom verifier or debugging an existing one.

---

## The five required vars

The kernel stamps these on every verifier spawn. **All five must be
non-empty** or the verifier exits with `StubEnvError::Missing("…")`.

| Variable | Stamped value | Purpose |
|---|---|---|
| `RAXIS_VERIFIER_TOKEN` | 64 hex chars (256-bit single-use) | Single-use auth token; sent back in the `WitnessSubmission` body. The kernel rejects a submission whose token doesn't match the one it stamped. |
| `RAXIS_TASK_ID` | The task's `task_id` | Echoed into `WitnessSubmission.task_id`. Used by the kernel for attribution. |
| `RAXIS_GATE_TYPE` | The verifier's `gate_type` | Echoed into `WitnessSubmission.gate_type`. Used by the merge gate to match the witness against the task's verifier list. |
| `RAXIS_EVALUATION_SHA` | 40 hex chars (commit SHA) | The commit-ish the verifier ran against. Echoed back; the kernel verifies the verifier ran against the right snapshot. |
| `RAXIS_KERNEL_SOCKET` | Path to a UDS | The kernel's verifier socket. The verifier opens it and sends the submission. |

---

## One optional var

| Variable | Stamped value | Purpose |
|---|---|---|
| `RAXIS_WORKTREE_ROOT` | Absolute path | The worktree the verifier runs in. Most verifiers `cd` to this directly; the kernel pre-checks-out the right commit. |

---

## What the verifier does with them

```text
1. Read all five required env vars; exit if any is missing.
2. cd $RAXIS_WORKTREE_ROOT (if set).
3. Run the verifier check (e.g., `cargo test`).
4. Build a WitnessSubmission:
     {
       "verifier_token":  $RAXIS_VERIFIER_TOKEN,
       "task_id":         $RAXIS_TASK_ID,
       "gate_type":       $RAXIS_GATE_TYPE,
       "evaluation_sha":  $RAXIS_EVALUATION_SHA,
       "result_class":    "Pass" | "Fail" | "Inconclusive",
       "body":            <free-form JSON, e.g. test counts>,
     }
5. Connect to $RAXIS_KERNEL_SOCKET (UDS).
6. Send the submission as a single newline-terminated JSON line.
7. Exit with the status the verifier wants.
```

The kernel:

1. Reads the submission.
2. Looks up the verifier_token in `verifier_tokens_seen`.
3. Verifies (task_id, gate_type, evaluation_sha) match what was
   stamped.
4. Records the witness under `<data-dir>/witness/<sha>` (content-
   addressed by submission body SHA-256).
5. Marks the verifier task complete.

A duplicate submission (same token reused) is rejected; the verifier
ran twice (or the token leaked).

---

## Example — minimal verifier

```bash
#!/usr/bin/env bash
set -e

# 1. Read env.
: "${RAXIS_VERIFIER_TOKEN:?missing}"
: "${RAXIS_TASK_ID:?missing}"
: "${RAXIS_GATE_TYPE:?missing}"
: "${RAXIS_EVALUATION_SHA:?missing}"
: "${RAXIS_KERNEL_SOCKET:?missing}"

# 2. cd into the worktree.
cd "${RAXIS_WORKTREE_ROOT:-.}"

# 3. Run the check.
if cargo test --workspace --quiet; then
    RESULT="Pass"
else
    RESULT="Fail"
fi

# 4. Build the submission.
SUBMISSION=$(cat <<EOF
{"verifier_token":"$RAXIS_VERIFIER_TOKEN","task_id":"$RAXIS_TASK_ID","gate_type":"$RAXIS_GATE_TYPE","evaluation_sha":"$RAXIS_EVALUATION_SHA","result_class":"$RESULT","body":{}}
EOF
)

# 5. Send to the kernel socket.
echo "$SUBMISSION" | nc -U "$RAXIS_KERNEL_SOCKET"
```

This is what the `raxis-verifier-rust-starter` does internally,
plus richer body content.

---

## The stub harness (`raxis-verifier-stub`)

The kernel ships `raxis-verifier-stub`, a debugging tool that
honours all five env vars and reads three more for testing:

| Variable | Effect |
|---|---|
| `RAXIS_STUB_RESULT_CLASS` | One of `Pass`, `Fail`, `Inconclusive`. Defaults to `Pass`. Forces the stub's verdict. |
| `RAXIS_STUB_BODY_JSON` | A JSON object stamped into the witness body. |
| `RAXIS_STUB_SLEEP_MS` | Milliseconds to sleep before submitting (simulates slow checks). |
| `RAXIS_STUB_SKIP_SEND` | `"1"` skips the submission entirely (simulates a verifier that crashed pre-submit). |

Use the stub as a verifier image during integration testing — pin
its result and body to drive the merge gate without writing a real
check.

---

## Common failure modes (verifier-side)

| Symptom | Fix |
|---|---|
| `RAXIS_VERIFIER_TOKEN missing` | Verifier was launched outside the kernel's spawn path. Don't run it manually. |
| `connect: $RAXIS_KERNEL_SOCKET No such file` | The kernel exited / crashed mid-verifier. Check `<data-dir>/runtime/`. |
| Witness submitted but kernel ignores it | Token mismatch (token was reused or stale). The kernel emits `WitnessSubmissionRejected` with the reason. |
| Kernel times out the verifier | The verifier exceeded `[[gates]] max_wall_seconds` or per-task `max_wall_seconds`. Raise the cap or fix the verifier's runtime. |

---

## Reference: relevant kernel-internal state

| Surface | Purpose |
|---|---|
| `<data-dir>/witness/<sha>` | Content-addressed witness storage. |
| `verifier_tokens_seen` (kernel.db) | Token replay-protection table. |
| `raxis verifiers` | Live list of outstanding verifier tokens. |
| `raxis witnesses <task_id>` | Witnesses for one task. |
| `RAXIS_KERNEL_SIGNING_KEY_HEX` / `RAXIS_KERNEL_SIGNING_KEY_BYTES_PATH` | Build-time vars consumed by the canonical-images `build.rs`; not runtime config. |

---

## Variations

- **Custom verifier image.** Build an OCI image whose entrypoint
  reads these env vars; publish via `[[vm_images]]`; reference from
  `[[tasks.verifiers]] image`.
- **Stub-driven integration tests.** Use `raxis-verifier-stub` with
  `RAXIS_STUB_RESULT_CLASS=Pass` to force a green merge in tests
  without setting up real `cargo test` infrastructure.
- **Slow / flaky verifiers.** `RAXIS_STUB_SLEEP_MS=10000` simulates
  a 10-second check; useful for testing wall-clock cap behaviour.
