# Configure the default executor image

> **Topic:** Setup | **Time to read:** ~3 min | **Complexity:** ⭐⭐ Intermediate

`[default_executor_image]` is the policy block that names the
operator-published `[[vm_images]]` alias used to spawn an Executor
when its `[[tasks]]` block does not declare `vm_image`. Without
this block, omitting `vm_image` falls back to the canonical starter
image bundled with the kernel — fine for hello-world plans, but
typically too small for real workloads.

---

## Prerequisites

- A genesis-completed install. `RAXIS_DATA_DIR`,
  `RAXIS_OPERATOR_KEY` exported.
- An OCI image you've built and signed for use as an Executor base.
  Building the image is out of scope; this recipe assumes you already
  have a digest like
  `sha256:7c1f...e2`.

---

## Step 1 — Publish the image in `[[vm_images]]`

Edit `policy.toml`:

```toml
[[vm_images]]
name                       = "rust-toolchain-2026-05"
oci_digest                 = "sha256:7c1f4b2c0d4f1e9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5"
linux_kernel_version_min   = "5.10"
egress_allowlist           = ["registry.npmjs.org", "static.crates.io"]
```

Field reference:

| Field | Required | Effect |
|---|---|---|
| `name` | yes | The alias operators reference from `[[tasks]] vm_image` and `[default_executor_image]`. |
| `oci_digest` | yes | Pinned content-addressed digest. The kernel re-resolves this against the image cache at every spawn — a registry rotation between admission and activation is observed. |
| `linux_kernel_version_min` | optional | Minimum Linux version inside the image. The kernel's verifier rejects an image that boots a kernel below this version. |
| `egress_allowlist` | optional | Per-image upper bound on egress hosts. Plan-level `allowed_egress` must be a subset. |

You can declare as many `[[vm_images]]` blocks as you want — each
with a distinct `name`.

---

## Step 2 — Add the `[default_executor_image]` block

```toml
[default_executor_image]
alias = "rust-toolchain-2026-05"
```

The single field `alias` MUST match a `[[vm_images]] name` declared
in the same policy. Validation rejects a dangling alias at signing
time.

If the `[default_executor_image]` block is **omitted**, the kernel
spawns Executors from the canonical starter image (a minimal
Alpine-based rootfs with `git`, `bash`, and the planner binary —
nothing else). For demo plans this is fine. For real plans that
expect `cargo`, `npm`, `python3`, etc., set the default explicitly.

---

## Step 3 — Sign and verify

```bash
raxis policy sign \
  "$RAXIS_DATA_DIR/policy/policy.toml" \
  --key "$RAXIS_OPERATOR_KEY"

# Confirm the new alias is visible.
raxis policy show \
  | sed -n '/^\[\[vm_images\]\]$/,/^\[\[/p'
raxis policy show \
  | sed -n '/^\[default_executor_image\]$/,/^\[/p'
```

---

## Step 4 — Run a plan that omits `vm_image`

```toml
# plan.toml
[[tasks]]
task_id            = "demo"
session_agent_type = "Executor"
clone_strategy     = "blobless"
path_allowlist     = ["src/"]
description        = """Build the project with cargo."""
# vm_image NOT set → kernel uses the default
```

Submit it. The `SubTaskActivated` audit event names the alias the
kernel resolved:

```text
{"event":"SubTaskActivated","task_id":"demo","vm_image_alias":"rust-toolchain-2026-05","oci_digest":"sha256:7c1f..."}
```

If the alias resolves to a digest that's not in the local image cache
the kernel pulls + verifies it on first use; subsequent activations
hit the cache.

---

## Reviewer images

`[default_executor_image]` does **not** apply to Reviewers. Reviewer
tasks are forbidden from declaring `vm_image` (the parser rejects
any non-empty value with `FAIL_REVIEWER_VM_IMAGE_NOT_ALLOWED`); they
always run from the kernel-canonical Reviewer image, which has no
network device, no shell, and only the planner binary
(`INV-PLANNER-HARNESS-02`).

---

## Common failure modes

| Symptom | Fix |
|---|---|
| `default_executor_image: alias "..." not declared in [[vm_images]]` | The block references an alias that isn't published. Re-check spelling; `[default_executor_image]` is validated against `[[vm_images]]` at signing time. |
| `image_cache: digest mismatch` at activation | The OCI registry returned bytes whose SHA-256 doesn't match the pinned `oci_digest`. Either the digest in policy is wrong or the registry was poisoned. **Do not** auto-update the policy — investigate. |
| `egress_allowlist subset violation` | A plan's `[[tasks]] allowed_egress` lists hosts not in the image's `egress_allowlist`. Tighten the plan or broaden the image policy. |
| `linux_kernel_version_min not satisfied` | The image boots an older kernel than the policy requires. Rebuild the image with a newer base. |

---

## Reference: env vars + commands

| Variable / command | Purpose |
|---|---|
| `RAXIS_OPERATOR_KEY` | Path to the operator PEM, used by `raxis policy sign`. |
| `raxis policy sign` | Re-signs `policy.toml` after every edit. |
| `raxis policy show` | Renders the active policy bundle for inspection. |

---

## Variations

- **Per-task override.** Even with the default set, an individual
  task can pin its own image: `[[tasks]] vm_image = "build-jvm-21"`.
  The per-task setting wins; the default kicks in only when the
  field is absent.
- **Disable the default.** Remove the `[default_executor_image]`
  block; Executors that don't declare their own `vm_image` boot from
  the kernel-canonical starter image.
- **Multiple toolchains.** Publish one alias per toolchain
  (`rust-2026-05`, `node-22`, `python-3.12`). Set the default to
  whichever covers most plans; tasks that need a different image
  set `vm_image` explicitly.
