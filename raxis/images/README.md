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

The builder is hermetic; it never invokes a package manager or makes
a network call. To build a manifest from a populated `rootfs/`:

```bash
$ export RAXIS_IMAGE_SIGNING_KEY=/path/to/raxis-image-signing-key.hex   # 0o600 file
$ cargo run -p raxis-image-builder -- build reviewer
$ cargo run -p raxis-image-builder -- build orchestrator
$ cargo run -p raxis-image-builder -- build executor-starter
```

Output lands at `out/<role>.manifest.toml` — a TOML manifest carrying
the per-file SHA-256s, the bundle hash, and the Ed25519 signature
binding the bundle hash to the kernel signing key.

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
