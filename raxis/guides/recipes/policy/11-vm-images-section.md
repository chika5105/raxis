# `[[vm_images]]` — operator-published VM image registry

> **Topic:** Policy reference | **Time to read:** ~3 min | **Complexity:** ⭐⭐ Intermediate

`[[vm_images]]` declares the OCI-pinned VM images operators publish
for use by Executor and Verifier sessions. Each entry binds a
human alias (referenced by plans) to a content-addressed digest, a
role restriction, and a minimum guest-Linux kernel version. The
Reviewer and Orchestrator images are kernel-canonical and **cannot**
be operator-published (`INV-PLANNER-HARNESS-02` /
`INV-PLANNER-HARNESS-05`).

---

## Field reference

| Field | Type | Required | Effect |
|---|---|---|---|
| `name` | `String` | yes | Alias referenced from `[[tasks]] vm_image` and `[default_executor_image] alias`. Must match `^[a-z][a-z0-9-]{0,63}$`. The reserved alias `raxis-verifier-symbol-index` (the kernel-canonical symbol-index image) is rejected. |
| `oci_digest` | `String` | yes | Pinned digest in the form `sha256:<64 lower-hex>`. The kernel re-resolves this against the image cache at every spawn — registry rotation between admission and activation is observed. |
| `role_restriction` | `Vec<String>` | yes (≥ 1 entry) | Roles that may use this image. Allowed values: `"Executor"`, `"Verifier"`. `"Reviewer"` and `"Orchestrator"` are structurally rejected at policy load. |
| `linux_kernel_version_min` | `String` | yes | Minimum guest kernel version (e.g. `"5.14"`). Must be ≥ `5.14` (`INV-PLANNER-HARNESS-03` — cgroup v2 controller availability). |
| `description` | `String` | optional | Free-text description; surfaced by `raxis policy show`. |

`name` uniqueness is enforced; duplicates fail policy load with
`FAIL_POLICY_VM_IMAGE_DUPLICATE`.

---

## Example — Rust toolchain Executor image

```toml
[[vm_images]]
name                     = "rust-toolchain-2026-05"
oci_digest               = "sha256:7c1f4b2c0d4f1e9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5"
role_restriction         = ["Executor"]
linux_kernel_version_min = "5.14"
description              = "Rust 1.78 + cargo + git + ripgrep — May 2026 monthly bake."
```

## Example — multi-role verifier image

```toml
[[vm_images]]
name                     = "fuzzer-arsenal-2026-05"
oci_digest               = "sha256:a3b8d0f1e2c4b5d6a7c8e9d0f1e2c4b5d6a7c8e9d0f1e2c4b5d6a7c8e9d0f1e"
role_restriction         = ["Executor", "Verifier"]
linux_kernel_version_min = "5.14"
description              = "AFL++ + libFuzzer + honggfuzz — usable as both a fuzzing Executor and a fuzz-as-verifier."
```

## Example — disallowed: Reviewer / Orchestrator role

```toml
# WRONG — fails policy load:
[[vm_images]]
name             = "custom-reviewer"
role_restriction = ["Reviewer"]      # FAIL_REVIEWER_VM_IMAGE_NOT_ALLOWED
```

The Reviewer image is fixed by the kernel; you cannot publish a
custom one. Use `context = "..."` in the Reviewer task block to
shape its review behaviour instead.

---

## How a plan binds to an image

```toml
# plan.toml
[[tasks]]
task_id            = "rust-build"
session_agent_type = "Executor"
clone_strategy     = "blobless"
path_allowlist     = ["src/"]
vm_image           = "rust-toolchain-2026-05"      # ← matches [[vm_images]] name
description        = """Build the project."""
```

If `vm_image` is omitted, the kernel uses
`[default_executor_image] alias` (when set), or the kernel-canonical
`raxis-executor-starter` image as last resort.

---

## Common failure modes

| Symptom | Fix |
|---|---|
| `FAIL_POLICY_VM_IMAGE_NAME_INVALID` | Alias contains uppercase, underscore, or starts with a digit. Rename. |
| `FAIL_POLICY_RESERVED_VM_IMAGE_NAME` | Trying to reuse `raxis-verifier-symbol-index`. Pick a different name. |
| `FAIL_POLICY_VM_IMAGE_DIGEST_INVALID` | Digest is missing the `sha256:` prefix or contains non-hex / wrong length. |
| `FAIL_POLICY_VM_IMAGE_LINUX_KERNEL_VERSION_MIN_REQUIRED` | Add `linux_kernel_version_min`. Pre-V2.5 the field was optional; V2.5+ requires it for `INV-PLANNER-HARNESS-03`. |
| `FAIL_REVIEWER_VM_IMAGE_NOT_ALLOWED` | Don't list `"Reviewer"` in `role_restriction`; Reviewers can't be operator-published. |
| `image_cache: digest mismatch` at activation | The pulled image's SHA-256 doesn't match the pinned `oci_digest`. Either the digest in policy is wrong or the registry was poisoned. **Do not** auto-update; investigate. |
| Plan fails admission with `FAIL_VM_IMAGE_NOT_DECLARED` | The plan's `vm_image` doesn't match any `[[vm_images]] name`. Spelling check, then re-sign policy. |

---

## Reference: how to compute / inspect digests

```bash
# Resolve a tag to a digest (assumes you've authenticated to the registry).
crane digest registry.example.com/rust-toolchain:2026-05
# → sha256:7c1f4b2c0d4f1e9a...

# OR — pull the image and verify locally.
docker pull registry.example.com/rust-toolchain@sha256:7c1f...
docker image inspect rust-toolchain | jq -r '.[0].RepoDigests[0]'
```

The digest you paste into policy must match exactly the bytes the
kernel will pull at activation time.

---

## Variations

- **Tag-based aliases.** Don't paste a tag (`rust:2026-05`); always
  use the digest. The kernel rejects any non-`sha256:`-prefixed
  value at load.
- **One image per toolchain.** Publish one alias per toolchain
  family (`rust-2026-05`, `node-22-2026-05`, `python-3.12-2026-05`).
  Plans pick the right alias per task.
- **Pinning bake date.** Append the bake month to the alias
  (`-2026-05`); rotate by publishing the next month and updating
  plans. Keep the previous alias around for forensic reproducibility.
