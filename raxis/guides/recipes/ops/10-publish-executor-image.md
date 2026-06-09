# Publish a new Executor VM image

> **Topic:** Operations | **Time to read:** ~4 min | **Complexity:** ⭐⭐⭐ Advanced

Operators publish **Executor** VM images. The Reviewer and
Orchestrator images are kernel-canonical (`raxis-reviewer-core`
and `raxis-orchestrator-core`) and CANNOT be operator-published —
attempting it fails at policy load with
`FAIL_REVIEWER_VM_IMAGE_NOT_ALLOWED`
(`INV-PLANNER-HARNESS-02`) or
`FAIL_ORCHESTRATOR_VM_IMAGE_NOT_ALLOWED`
(`INV-PLANNER-HARNESS-05`).

End-to-end here: build, sign, install, and reference an Executor
image from a plan.

---

## Concepts

An Executor VM image hosts:

- The `raxis-planner-executor` binary (the Executor side of
  `planner-core`'s driver).
- A toolchain matched to the repo's language: `git`, the language's
  build tool (`cargo`, `npm`, `go`, etc.), test runners.
- An entrypoint that reads `RAXIS_PLANNER_*` env vars and starts
  the planner.

Sessions are isolated by, in decreasing strength:

- A microVM (Firecracker / similar) — strong isolation, default
  for production.
- A container — weaker but cheaper.
- Process-only fallback — development-only via
  `RAXIS_UNSAFE_FALLBACK_ISOLATION` (with a mandatory reason
  string in `RAXIS_UNSAFE_FALLBACK_ISOLATION_REASON`).

The Reviewer image is kernel-bundled; you don't choose or build
one. The kernel verifies its digest at boot. The Orchestrator
image is the same — kernel-bundled, kernel-digest-verified, no
operator hook (`INV-PLANNER-HARNESS-06`).

---

## Steps

### 1. Build the image

Example — a Rust-focused Executor:

```dockerfile
# Dockerfile.executor-rust
FROM rust:1.83-slim

RUN apt-get update && apt-get install -y \
      git ca-certificates jq \
    && rm -rf /var/lib/apt/lists/*

COPY raxis-planner-executor /usr/local/bin/raxis-planner-executor
COPY entrypoint              /usr/local/bin/entrypoint

ENTRYPOINT ["/usr/local/bin/entrypoint"]
```

`entrypoint`:

```bash
#!/usr/bin/env bash
set -euo pipefail

: "${RAXIS_KERNEL_SOCKET?missing}"
: "${RAXIS_TASK_ID?missing}"
: "${RAXIS_PLANNER_KSB?missing}"

cd "$RAXIS_WORKTREE_ROOT"
exec raxis-planner-executor
```

Build:

```bash
docker build -t my-org/raxis-executor-rust:v1 -f Dockerfile.executor-rust .
docker save my-org/raxis-executor-rust:v1 | gzip > /tmp/executor-rust-v1.tar.gz
```

### 2. Sign the image

```bash
raxis verifiers sign \
  --image  /tmp/executor-rust-v1.tar.gz \
  --signing-key "$RAXIS_IMAGE_SIGNING_KEY" \
  --out    /tmp/executor-rust-v1.signed
```

(The `verifiers sign` subcommand handles both verifier and Executor
images; the difference is the `role_restriction` in the policy
entry.)

### 3. Install in policy

```bash
raxis verifiers install /tmp/executor-rust-v1.signed \
  --role-restriction Executor \
  --command "/usr/local/bin/entrypoint" \
  --description "Rust Executor (rust 1.83, cargo, git)"
# Output:
# image_alias:  executor-rust-v1
# image_sha:    sha256:9c41...
# state:        ready
# role_restriction: ["Executor"]
```

Or edit `[[vm_images]]` directly and re-sign policy:

```toml
[[vm_images]]
name              = "executor-rust-v1"
image_digest      = "sha256:9c41..."
image_signed_by   = "8a4f..."     # signer kid
role_restriction  = ["Executor"]   # Executor and/or Verifier ONLY
linux_kernel_version_min = "5.14"
description       = "Rust Executor"
```

The kernel rejects `role_restriction` containing `"Reviewer"` or
`"Orchestrator"` at policy load:

```bash
raxis policy sign /tmp/policy.toml --key /tmp/op.key
# If you set role_restriction = ["Reviewer"]:
#   FAIL_REVIEWER_VM_IMAGE_NOT_ALLOWED: [[vm_images]] name = "..."
#   declares role_restriction = "Reviewer"; the Reviewer image is
#   kernel-canonical and cannot be operator-published.
```

### 4. Set as default (optional)

```toml
[default_executor_image]
name = "executor-rust-v1"   # used when [[tasks]].vm_image is omitted
```

Re-sign policy.

### 5. Reference from plans (or rely on default)

Per-task override:

```toml
[[tasks]]
task_name            = "implementer"
session_agent_type = "Executor"
vm_image           = "executor-rust-v1"
```

If omitted, the kernel uses `[default_executor_image]`.

For a Reviewer task, you do NOT set `vm_image` — the kernel-canonical
`raxis-reviewer-core` is used. Setting any `vm_image` on a
Reviewer task triggers `FAIL_REVIEWER_VM_IMAGE_NOT_ALLOWED` at
admission.

### 6. Test

```bash
INIT="$(raxis submit plan ./test-plan.toml --no-dry-run | awk '/^Initiative / {print $2} /^initiative_id:/ {print $2}')"
raxis plan approve "$INIT"
raxis sessions show <executor_session_id>
# vm_image_alias should be executor-rust-v1.
raxis log "$INIT" --kind SessionMinted | jq '.payload.vm_image_alias'
```

---

## Image hygiene

- **Pin everything.** Never floating tags — the digest must be a
  sha. Repeatable runs depend on this.
- **Minimize.** Don't ship the entire ecosystem; just what the
  Executor planner needs. Smaller images pull faster.
- **No secrets.** The image is shared across sessions; secrets
  must come via credential proxies (`[[tasks.credentials]]`),
  never baked in.
- **Versioned.** Always a version suffix in the alias (`-v1`,
  `-v2`) so you can roll back by pointing
  `[default_executor_image]` at the older one.
- **Don't try to publish Reviewer or Orchestrator images.** They
  are kernel-canonical. The "alternative Reviewer toolset" you
  might want is structurally not allowed — the Reviewer
  intentionally has a static, narrow tool surface
  (`INV-PLANNER-HARNESS-01`).

---

## Common errors

| Symptom | Fix |
|---|---|
| `FAIL_REVIEWER_VM_IMAGE_NOT_ALLOWED` at policy sign | Don't set `role_restriction = ["Reviewer"]` on a `[[vm_images]]` entry. Reviewer image is kernel-canonical. |
| `FAIL_ORCHESTRATOR_VM_IMAGE_NOT_ALLOWED` at policy sign | Same, for Orchestrator. |
| Session minted but exits immediately | Entry script error. Check `journalctl -u raxis-kernel` for the session's stdout/stderr capture. |
| `kernel: image_alias not found in policy` | Image not installed; re-run `verifiers install` and `raxis policy sign`. |
| `kernel: image signature invalid` | The signer kid in `image_signed_by` doesn't match `RAXIS_IMAGE_VERIFY_KEY`. |
| Planner connects but immediately fails authn | `RAXIS_PLANNER_KSB` not forwarded; the entrypoint must not strip env vars. |
| Image too big to pull in time | Pre-stage to the host's local registry, or accept the cold-start cost on first use. |

---

## Reference

| Command / Surface | Purpose |
|---|---|
| `raxis verifiers` / `verifiers sign` / `verifiers install` | Image lifecycle (Executor + Verifier images). |
| [policy/11-vm-images-section](../policy/11-vm-images-section.md) | Schema. |
| [env/11-planner-env-vars](../env/11-planner-env-vars.md) | Env vars planner subprocesses see. |
| `INV-PLANNER-HARNESS-02` (`specs/v2/planner-harness.md §4.5`) | Reviewer image is kernel-canonical. |
| `INV-PLANNER-HARNESS-05` (`specs/v2/planner-harness.md §4.7`) | Orchestrator image is kernel-canonical. |
| `crates/policy/src/bundle.rs::validate_vm_images` | Where the rejection fires. |

---

## Variations

- **Per-language Executor image.** A monorepo with mixed languages
  ships one Executor image per language (Rust, Python, Go); plans
  pick at the task level via `vm_image`.
- **GPU Executor.** Bake the CUDA toolchain; larger image, longer
  pulls; pair with a dedicated lane priority.
- **Air-gapped install.** Pre-stage the signed image bundle on the
  host's local registry; the kernel won't fetch from external
  registries.
- **Verifier-only image.** Use the same publishing flow with
  `role_restriction = ["Verifier"]` for verifier images that
  don't fit the cargo-test / rg / pytest defaults — see
  [`ops/09-publish-verifier-image`](./09-publish-verifier-image.md).
