# RAXIS canonical-image source dirs

This directory is the source-of-truth for the three RAXIS-built VM
images:

| Role               | Source dir                  | Status                                    |
| ------------------ | --------------------------- | ----------------------------------------- |
| Reviewer           | `reviewer-core/`            | Kernel-canonical (`INV-PLANNER-HARNESS-02`) |
| Orchestrator       | `orchestrator-core/`        | Kernel-canonical (`INV-PLANNER-HARNESS-05`) |
| Executor (starter) | `executor-starter/`         | Operator opt-in default                   |

Each directory contains:

- `manifest.toml` — build-input pin (role, kernel version,
  `SOURCE_DATE_EPOCH`, mkfs.erofs / tar / zstd versions).
- `Containerfile` — the deterministic recipe used to build the
  rootfs in CI. Operators do not run this themselves; the recipe
  lives in-tree so changes are reviewed alongside the kernel.
- `verify.sh` — POSIX-shell smoke test invoked by the builder
  after assembling the rootfs, enforcing the
  `INV-PLANNER-HARNESS-01/02/05` structural bans.
- `rootfs/` (gitignored) — the assembled rootfs the builder hashes.
  Populated by the per-release pipeline (see below); never checked
  into git.

## Building locally

The end-to-end driver is **`cargo xtask images bake`** — one command
that runs preflight, stages `vmlinux`, bakes each role's rootfs from
its `Containerfile`, cross-compiles the planner agent, packs the tree
into a signed cpio.gz initramfs, and writes the manifest. Operators
should not invoke `raxis-image-builder` directly:

```bash
$ export RAXIS_INSTALL_DIR="$HOME/.raxis-install"
$ cargo xtask images bake                       # bake every role
$ cargo xtask images bake --role orchestrator   # or one role at a time
```

The bake is hermetic — it never invokes a package manager or makes
a network call. Output lands at
`$RAXIS_INSTALL_DIR/images/<role>-<kver>.img` (initramfs) paired with
`<role>-<kver>.manifest.toml` carrying the per-file SHA-256s, bundle
hash, and the Ed25519 signature binding the bundle hash to the kernel
signing key.

`raxis-image-builder` is the underlying crate the bake invokes; it
remains documented here for the rare case where a developer needs to
re-sign an existing rootfs without re-running the full pipeline.

To verify a manifest:

```bash
$ cargo run -p raxis-image-builder -- verify out/reviewer-core.manifest.toml \
    --public-key /path/to/raxis-image-signing-key.pub
```

The `verify` subcommand performs the same four-step check the kernel
performs at boot: schema-version, recomputed-bundle-hash equality,
signing-key fingerprint, Ed25519 signature.

## Determinism guarantee

The builder is byte-deterministic for identical `rootfs/` content;
this is enforced by the in-tree test
`crates/image-builder/src/lib.rs::build_and_sign_is_byte_deterministic_for_identical_rootfs`.
CI reruns the build twice on every PR and asserts the produced
manifests are identical (`bundle_hash` and `signature` byte-equal).

## Distribution

Per `planner-harness.md §14.4`, the produced manifests for the
Reviewer + Orchestrator images are embedded into the kernel binary
via `include_bytes!`; the EROFS rootfs blob ships alongside the
kernel binary at `$RAXIS_INSTALL_DIR/images/<role>-<kernel_version>.img`.
The Executor starter manifest is distributed but not embedded —
operators consume it through the policy bundle's `[[vm_images]]`
table.
