# Bring Your Own Executor Image (BYO)

> **Topic:** Operations | **Time to read:** ~7 min | **Complexity:** ⭐⭐⭐⭐ Expert

End-to-end recipe for shipping a **custom Executor VM image** (your
own Containerfile, your own toolchain) and binding it as the default
that every Executor task in your fleet boots from. The kernel
re-verifies your declared `oci_digest` against the on-disk rootfs
at every spawn — fail-closed with `OperatorImageDigestMismatch` if
the bytes ever drift from the policy declaration
(`INV-OPERATOR-CUSTOM-IMAGE-01`).

The Reviewer and Orchestrator images are kernel-canonical (shipped
as part of the RAXIS release, digest pinned at kernel build time)
and CANNOT be operator-published. The BYO surface is Executor- and
Verifier-only (`INV-IMAGE-RESOLUTION-PER-ROLE-01`).

> **What this recipe is for.** Shipping a non-default toolchain
> stack (e.g. Python 3.12 + Node 22 instead of the kernel-canonical
> Python 3.11 + Node 20). For the simpler "publish a Rust Executor"
> flow that uses the existing `raxis verifiers` CLI workflow, see
> [`ops/10-publish-executor-image`](./10-publish-executor-image.md).
> This recipe walks the Containerfile-up-and-policy-down path that
> the BYO end-to-end test
> (`kernel/tests/extended_e2e_byo_executor_image.rs`) exercises.

---

## Concepts

A BYO Executor image is just an OCI image that:

- Carries the toolchain your Executor tasks need (interpreters,
  compilers, package managers, etc.).
- Sets PATH / env vars so `raxis-planner-executor` (the Executor
  side of `planner-core`) can find them.
- Has its rootfs SHA-256 declared in your signed `policy.toml` as
  the trust anchor.

The kernel binds your image to the Executor role at three layers:

1. **Policy load.** `[[vm_images]] role_restriction = ["Executor"]`
   admits the alias for Executor binding only;
   `["Reviewer"]` / `["Orchestrator"]` are structurally rejected
   with `FAIL_REVIEWER_VM_IMAGE_NOT_ALLOWED` /
   `FAIL_ORCHESTRATOR_VM_IMAGE_NOT_ALLOWED`.
2. **Plan admission.** `[[plan.tasks]] vm_image = "..."` on a
   Reviewer task is rejected with `reviewer_image_not_allowed`.
3. **Activation.** Every Executor session-spawn that resolves to
   your alias re-hashes the on-disk rootfs and compares against
   the declared `oci_digest`. Mismatch fires
   `SecurityViolationDetected { OperatorImageDigestMismatch }`
   (Critical-priority notification) and refuses the activation.

Cross-link: see `specs/v2/canonical-images.md §3` for the full
trust-contract walkthrough and `specs/v2/image-cache.md §4` for the
on-disk cache layout your image lands in.

---

## Steps

### 1. Author the Containerfile

The sample lives at
`raxis/live-e2e/seed/byoi-executor/Containerfile` (Python 3.12 +
Node 22 on `python:3.12.7-slim-bookworm`). Reusable shape:

```dockerfile
# Pin the base image to a specific patch version for reproducibility.
FROM python:3.12.7-slim-bookworm AS base

ENV DEBIAN_FRONTEND=noninteractive
ENV LANG=C.UTF-8

RUN apt-get update && apt-get install --no-install-recommends -y \
        bash ca-certificates coreutils curl findutils git \
        gnupg grep jq less sed tar xz-utils \
    && rm -rf /var/lib/apt/lists/*

RUN ln -sf /usr/local/bin/python3.12 /usr/local/bin/python3 \
    && python3.12 --version

RUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
    && apt-get install --no-install-recommends -y nodejs \
    && rm -rf /var/lib/apt/lists/* \
    && node --version
```

Image hygiene:

- **Pin every layer.** Patch-versioned base, apt versions if you
  care about supply-chain hardening, NodeSource minor pin via the
  `setup_22.x` script.
- **Minimal toolchain.** Only what your Executor tasks need.
  Smaller images stage faster.
- **No secrets.** Credentials come via `[[tasks.credentials]]`,
  never baked into the rootfs.
- **No planner binary.** The harness overlays
  `raxis-planner-executor` onto the rootfs at stage time;
  baking it into the Containerfile would couple your image
  recipe to the kernel release cadence.

### 2. Build and export the rootfs

The kernel boots from a flat rootfs blob, not a multi-layer OCI
manifest, so the build pipeline is "build the OCI image, then
flatten it into a single rootfs.img":

```bash
# Build for the platform that matches your kernel host.
docker build \
  --platform linux/amd64 \
  -f raxis/live-e2e/seed/byoi-executor/Containerfile \
  -t local/byo-executor-py312-node22:dev \
  raxis/live-e2e/seed/byoi-executor/

# Export the rootfs as a tarball.
container=$(docker create local/byo-executor-py312-node22:dev)
docker export "$container" \
  | gzip -n > /tmp/byo-executor.rootfs.tar.gz
docker rm "$container"

# Convert to the on-disk shape the substrate boots from.
# (Production: use `raxis xtask images bake-rootfs` per
#  release-and-distribution.md §4.2; for one-off development you
#  can skip the EROFS conversion and stage the tar directly.)
```

For the actual production build pipeline, see
`xtask/src/images.rs::bake_rootfs` and
`specs/v2/release-and-distribution.md §4.2`. The end-to-end test
harness at
`kernel/tests/extended_e2e_support/byo_image.rs::bake_byo_executor_image_full`
demonstrates the same flow programmatically.

### 3. Compute the digest

```bash
# The digest is the SHA-256 of the rootfs blob the substrate
# will boot from. Hash the *exact* file you'll stage in step 4.
sha256sum /tmp/byo-executor.rootfs.tar.gz | awk '{ print "sha256:" $1 }'
# → sha256:9c41a5b8...
```

### 4. Stage in the kernel's OCI cache

The cache layout (see `image-cache.md §4`) is:

```text
$RAXIS_DATA_DIR/oci-cache/images/sha256/<aa>/<full>/
├── rootfs.img
├── manifest.json
└── config.json
```

`<aa>` is the first two hex chars of `<full>` (the 64-char SHA),
keeping each shard directory under ~256 entries.

```bash
DIGEST_HEX=9c41a5b8...                 # the 64-char hex from step 3
DATA_DIR="${RAXIS_DATA_DIR:-$HOME/.raxis/data}"
SHARD="${DIGEST_HEX:0:2}"
DEST="$DATA_DIR/oci-cache/images/sha256/$SHARD/$DIGEST_HEX"

mkdir -p "$DEST"
cp /tmp/byo-executor.rootfs.tar.gz "$DEST/rootfs.img"

# Synthesize the OCI sidecars the resolver expects (the
# PrePopulatedResolver doesn't talk to a registry, so it doesn't
# need a real OCI manifest — but the files must exist).
printf '{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:%s","size":0},"layers":[]}\n' \
    "$DIGEST_HEX" > "$DEST/manifest.json"
printf '{"created":"2026-05-13T00:00:00Z","architecture":"amd64","os":"linux","config":{"Env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"]}}\n' \
    > "$DEST/config.json"
```

The harness helper
`extended_e2e_support/byo_image.rs::stage_byo_image_in_oci_cache`
does the equivalent in Rust and is the canonical reference if
you need to script this out in a deployment pipeline.

### 5. Declare in `policy.toml`

```toml
[[vm_images]]
name                     = "byo-executor-py312-node22"
oci_digest               = "sha256:9c41a5b8..."   # paste from step 3
role_restriction         = ["Executor"]
linux_kernel_version_min = "5.14"
description              = "Python 3.12.7 + Node 22 LTS — BYO operator image."

[default_executor_image]
name = "byo-executor-py312-node22"
```

Field schema reference:
[`policy/11-vm-images-section`](../policy/11-vm-images-section.md).
Default-image semantics:
[`setup/09-default-executor-image`](../setup/09-default-executor-image.md).

### 6. Re-sign policy

```bash
raxis policy sign /etc/raxis/policy.toml --operator-key "$OPERATOR_KEY"
# Loads the bundle, validates [[vm_images]] (digest shape, role
# admit-list, kernel-version floor), and emits the signed
# bundle under $RAXIS_DATA_DIR/policy/.
```

If the digest, role admit-list, or kernel floor is malformed, this
step fails immediately:

| Symptom                                                  | Fix                                                                              |
| -------------------------------------------------------- | -------------------------------------------------------------------------------- |
| `FAIL_POLICY_VM_IMAGE_DIGEST_INVALID`                    | Digest missing `sha256:` prefix or wrong length / non-hex.                        |
| `FAIL_POLICY_VM_IMAGE_ROLE_RESTRICTION_REQUIRED`         | Add `role_restriction = ["Executor"]`.                                           |
| `FAIL_REVIEWER_VM_IMAGE_NOT_ALLOWED`                     | Don't include `"Reviewer"` in `role_restriction` — the Reviewer image is canonical. |
| `FAIL_ORCHESTRATOR_VM_IMAGE_NOT_ALLOWED`                 | Same, for `"Orchestrator"`.                                                       |
| `FAIL_POLICY_VM_IMAGE_LINUX_KERNEL_VERSION_MIN_REQUIRED` | Add `linux_kernel_version_min = "5.14"` (or higher).                              |

### 7. Submit a smoke initiative

```bash
cat > /tmp/byo-smoke.toml <<'EOF'
description = "BYO Executor smoke — confirm Python 3.12 + Node 22 are present."

[[plan.tasks]]
task_id            = "version-check"
session_agent_type = "Executor"
description        = """
  Run `bash -c 'python3.12 --version && node --version'` and surface the
  versions to the worktree log. Should print `Python 3.12.x` and `v22.x.x`.
"""
EOF

raxis submit plan /tmp/byo-smoke.toml
INIT=$(raxis initiative list --state Draft --json | jq -r '.[0].initiative_id')
raxis plan approve "$INIT"
```

### 8. Verify the audit trail (Tier 1 mechanical witness)

The kernel emits `VmImageResolved` BEFORE the Executor VM spawn.
This is your "which bytes booted this session?" mechanical witness.

```bash
raxis log "$INIT" --kind VmImageResolved | jq '
  .payload | {
    session_id,
    task_id,
    initiative_id,
    alias,
    oci_digest,
    agent_role
  }
'
# Expected output:
# {
#   "session_id":    "<uuid>",
#   "task_id":       "version-check",
#   "initiative_id": "<initiative-uuid>",
#   "alias":         "byo-executor-py312-node22",
#   "oci_digest":    "sha256:9c41a5b8...",     <-- matches your declaration
#   "agent_role":    "Executor"
# }
```

`agent_role` is normatively constrained to `"Executor"` for the
BYO path; observing any other value is a kernel bug
(`INV-IMAGE-RESOLUTION-PER-ROLE-01`).

### 9. Verify the BashTool output (Tier 2 semantic witness)

```bash
SESSION=$(raxis log "$INIT" --kind VmImageResolved \
  | jq -r '.payload.session_id')
raxis sessions log "$SESSION" --kind BashToolStdout \
  | jq -r '.payload.stdout'
# Expected:
# Python 3.12.7
# v22.11.0
```

If you don't see the expected versions, your Containerfile didn't
land what you thought it landed — re-check step 1, re-bake (steps
2–4), re-sign policy (steps 5–6), re-submit (step 7).

---

## Negative-path: what happens on tamper

The trust contract's value is fail-closed behaviour. To exercise it
manually (or once, in staging, to confirm your audit pipeline):

```bash
# Flip the last byte of the staged rootfs.
DEST="$DATA_DIR/oci-cache/images/sha256/$SHARD/$DIGEST_HEX/rootfs.img"
SIZE=$(stat -c %s "$DEST")
LAST=$(tail -c 1 "$DEST" | od -An -tx1 | tr -d ' \n')
printf '\x00' | dd of="$DEST" bs=1 count=1 \
  seek=$((SIZE - 1)) conv=notrunc 2>/dev/null
# (Or use a real tampered image — the on-disk SHA just needs to
# diverge from the policy-declared sha256: digest.)

# Submit the same plan again.
raxis submit plan /tmp/byo-smoke.toml
INIT2=$(raxis initiative list --state Draft --json | jq -r '.[0].initiative_id')
raxis plan approve "$INIT2"

# Watch the audit trail. Activation MUST refuse.
raxis log "$INIT2" --kind SecurityViolationDetected | jq '
  .payload | {
    violation_kind,
    expected,
    actual,
    path
  }
'
# Expected:
# {
#   "violation_kind": "OperatorImageDigestMismatch",
#   "expected":       "sha256:9c41a5b8...",
#   "actual":         "sha256:<new-hash-after-flip>",
#   "path":           ".../oci-cache/images/sha256/9c/9c41.../rootfs.img"
# }

# The activation row is in PendingActivation; no VM spawned.
raxis sessions list --initiative "$INIT2"
# (no session for "version-check" — the activation was refused
# BEFORE spawn.)
```

The dashboard classifies every `SecurityViolationDetected` event
as `Critical`, so this also lights up your operator inbox /
notification channel.

To recover, **either**:

- Re-stage the rootfs whose SHA matches the policy declaration
  (re-run steps 2–4), **or**
- Re-bake from a new Containerfile, recompute the SHA (steps
  2–3), update `[[vm_images]] oci_digest` in policy, re-sign
  (step 6).

NEVER auto-update the policy digest from the on-disk hash — the
whole point of the contract is that a host-side write doesn't
silently propagate into a signed bundle.

---

## Reference

| Symbol / surface                                                 | Purpose                                                         |
| ---------------------------------------------------------------- | --------------------------------------------------------------- |
| `live-e2e/seed/byoi-executor/Containerfile`                      | Sample BYO recipe, exercised by the BYO live-e2e test.          |
| `kernel/tests/extended_e2e_support/byo_image.rs`                 | Harness primitives: bake, stage, inject, tamper.                |
| `kernel/tests/extended_e2e_byo_executor_image.rs`                | The end-to-end test that pins this recipe.                      |
| `crates/policy/src/bundle.rs::validate_vm_images`                | Where `FAIL_REVIEWER_VM_IMAGE_NOT_ALLOWED` etc. fire.           |
| `crates/image-cache/src/pre_populated.rs`                        | The resolver implementation that re-hashes your staged rootfs.  |
| `kernel/src/handlers/intent.rs::resolve_vm_image_override`       | Where `OperatorImageDigestMismatch` fires.                      |
| `specs/v2/canonical-images.md §3`                                | The trust-contract spec.                                        |
| `specs/v2/image-cache.md §4`                                     | The cache layout your rootfs lands in.                          |
| `specs/invariants.md §10.5` (`INV-OPERATOR-CUSTOM-IMAGE-01,02`)  | The normative trust contracts this recipe upholds.              |
| [`policy/11-vm-images-section`](../policy/11-vm-images-section.md) | Field-by-field schema reference for `[[vm_images]]`.            |
| [`setup/09-default-executor-image`](../setup/09-default-executor-image.md) | Wiring `[default_executor_image]`.                              |
| [`ops/10-publish-executor-image`](./10-publish-executor-image.md) | The simpler `raxis verifiers` CLI workflow for routine images.  |

---

## Variations

- **Per-task BYO override.** Skip `[default_executor_image]` and
  set `[[plan.tasks]] vm_image = "byo-executor-py312-node22"` only
  on the tasks that need this toolchain. Other Executor tasks
  fall back to the kernel-canonical `raxis-executor-starter`.
- **Multi-arch.** Build with both `--platform linux/amd64` and
  `--platform linux/arm64`, stage both rootfs blobs (different
  digests), and declare two `[[vm_images]]` entries (`-amd64` /
  `-arm64` suffix). The kernel host's arch picks the right
  alias via per-task plan logic; auto-arch resolution is on the
  V3 roadmap.
- **Air-gapped staging.** Step 4 needs no network; pre-stage the
  rootfs on a build host, copy to deployment hosts via your
  config-management tool of choice. The policy bundle (step 5)
  carries the same digest across all hosts; the kernel only
  refuses to boot if the on-disk bytes don't match.
- **Verifier-side BYO.** Add `"Verifier"` to `role_restriction`
  and reference the alias from a `[[verifiers]]` block. The
  current `VmImageResolved` audit-event surface is Executor-only;
  Verifier-side emission is on the roadmap (see
  `canonical-images.md §6`).
