# RAXIS V2 demo on macOS — Apple-VZ canonical-image path

This is the **single-file recipe for a fully-hermetic AVF demo on macOS**:
no Docker, no `mkfs.erofs`, no externally-published canonical images. It
walks you through cross-compiling the planner role binaries with `musl`,
packing them into signed cpio.gz initramfs blobs, dropping a real Linux
guest kernel under `$RAXIS_INSTALL_DIR/kernel/`, code-signing the
`raxis-kernel` host binary against the AVF entitlements, and finally
running through the V1 demo (genesis → plan submit → plan approve →
session create) with the V2 substrate live.

The recipe was hand-walked on `aarch64-apple-darwin` (Apple Silicon) for
this README. The same flow holds on `x86_64-apple-darwin` if you swap
the musl triple in §3 to `x86_64-unknown-linux-musl`.

For the V1 (no-microVM, no AVF) demo, see [`README.md`](./README.md).
For the live-infra E2E (Postgres + MongoDB + Anthropic on docker
compose), see [`raxis/kernel/tests/full_e2e_session_lifecycle.rs`](../kernel/tests/full_e2e_session_lifecycle.rs).

---

## Section 0 — Prerequisites

| Tool | Purpose | Notes |
|---|---|---|
| **Rust toolchain** (stable) | Build the workspace + `cargo xtask` | `rust-toolchain.toml` pins the channel automatically |
| **`aarch64-unknown-linux-musl`** target | Cross-compile planner binaries for the guest VM | `rustup target add aarch64-unknown-linux-musl` |
| **`musl-cross`** linker | Static link the cross-compiled planners | `brew install filosottile/musl-cross/musl-cross` |
| **`OpenSSL 3.x`** on `$PATH` | Mint operator Ed25519 keypair | macOS default `/usr/bin/openssl` is LibreSSL — `brew install openssl@3` |
| **`codesign`** (Xcode CLT) | Ad-hoc-sign the kernel binary against AVF entitlements | `xcode-select --install` |
| **A pre-built Linux kernel binary** | Boot the AVF guest | We point you at a downloadable `vmlinux-aarch64` in §6 |

The fastest way to land all of the above is the dedicated xtask
subcommand — it verifies (`--install`-flag escalates to install) the
brew packages, the rustup musl target, the cargo linker pin in
`~/.cargo/config.toml`, plus `codesign` / `cargo` on `$PATH`:

```bash
# verify-only (exits non-zero if anything is missing):
cargo xtask dev-prereqs

# verify + auto-install missing pieces (brew formulae and rustup target):
cargo xtask dev-prereqs --install
```

Equivalent manual verification, if you prefer to step through the
checks yourself:

```bash
openssl version                       # MUST show OpenSSL 3.x, NOT LibreSSL
rustup target list --installed | rg musl
which aarch64-linux-musl-gcc          # from `musl-cross`
codesign --version
cargo --version
```

> The `cargo xtask dev-prereqs` step also patches `~/.cargo/config.toml`
> idempotently with the snippet below so Cargo finds the musl linker.
> Pass `--skip-cargo-config` if you curate that file by hand.
>
> ```toml
> [target.aarch64-unknown-linux-musl]
> linker = "aarch64-linux-musl-gcc"
> ```

---

## Section 1 — Mint a local image-signing keypair

`cargo xtask dev-keys` writes the canonical signing key the
`raxis-image-builder` and the kernel both consume. The private half is
mode-`0600` and lives only on this developer's machine; the public half
is what the kernel-build embeds as the trust anchor for canonical-image
manifests.

```bash
cargo xtask dev-keys init                       # writes
                                                 #   $HOME/.config/raxis/keys/raxis-dev-signing.key.hex
                                                 #   $HOME/.config/raxis/keys/raxis-dev-signing.pub.hex

# Wire the public-key hex into the kernel build's trust anchor and the
# builder's signing-key path. Drop these into your shell init for
# subsequent `cargo build`s to pick them up.
export RAXIS_KERNEL_SIGNING_KEY_HEX="$(cat "$HOME/.config/raxis/keys/raxis-dev-signing.pub.hex")"
export RAXIS_IMAGE_SIGNING_KEY="$HOME/.config/raxis/keys/raxis-dev-signing.key.hex"
```

Reference: [`raxis/specs/v2/release-and-distribution.md §8`](../specs/v2/release-and-distribution.md).

---

## Section 2 — Build the workspace with the dev trust anchor live

The kernel binary embeds `RAXIS_KERNEL_SIGNING_KEY_HEX` as a
`build.rs`-pinned constant. Re-build now so the dev trust anchor is
live:

```bash
cargo build --release -p raxis-kernel -p raxis-cli -p raxis-gateway
```

The three binaries land at:

```text
target/release/raxis-kernel
target/release/raxis        # operator CLI; crate name `raxis-cli`
target/release/raxis-gateway
```

---

## Section 3 — Cross-compile the planner binaries for the guest

`cargo xtask images dev-stage` cross-compiles `raxis-planner-<role>` for
the guest target and stages the binary at
`raxis/images/<role>-core/rootfs/init`. The cpio writer in §4 walks that
tree to build the initramfs, and Linux execs `/init` as PID 1 inside
the AVF guest.

```bash
cargo xtask images dev-stage --role orchestrator
cargo xtask images dev-stage --role reviewer
cargo xtask images dev-stage --role executor-starter
```

Each invocation prints:

```json
{"level":"info","event":"dev_stage_begin","role":"raxis-planner-orchestrator", ... }
{"level":"info","event":"dev_stage_ok","role":"raxis-planner-orchestrator","binary":"...","staged_at":".../images/orchestrator-core/rootfs/init"}
```

> If `cargo build --target aarch64-unknown-linux-musl` fails with
> `error: linker "aarch64-linux-musl-gcc" not found`, you missed the
> `musl-cross` step in §0 or the `~/.cargo/config.toml` snippet. The
> `dev-stage` error message reproduces the install hint inline.

---

## Section 4 — Pack and sign the canonical images

`cargo xtask images build-all` walks each
`raxis/images/<role>-core/rootfs/` tree, packs it into a deterministic
cpio.gz initramfs blob via the in-repo `raxis-initramfs-builder`, calls
`raxis-image-builder` to emit a manifest stamped with
`image_format = RootfsInitramfsCpio`, signs the manifest with the
`dev-keys`-minted private key, and lays the pair out under
`$RAXIS_INSTALL_DIR/images/`:

```bash
export RAXIS_INSTALL_DIR="$HOME/.raxis-demo-install"
cargo xtask images build-all                    # builds every staged role
```

You can also build a single role: `cargo xtask images build-all --role orchestrator`.

After the run:

```bash
ls "$RAXIS_INSTALL_DIR/images"
# raxis-orchestrator-core-0.1.0.img
# raxis-orchestrator-core-0.1.0.manifest.toml
# raxis-reviewer-core-0.1.0.img
# raxis-reviewer-core-0.1.0.manifest.toml
# raxis-executor-starter-0.1.0.img
# raxis-executor-starter-0.1.0.manifest.toml
```

The manifest's `image_format = "RootfsInitramfsCpio"` is folded into the
`bundle_hash` and signed: dev-built images and prod-built EROFS images
cannot be confused at boot — the kernel's manifest verifier reads the
field via `read_verified_image_format` in `crates/canonical-images/`
and routes the rootfs into the AVF substrate accordingly.

> The on-disk `manifest.toml` fixtures (e.g.
> `raxis/images/orchestrator-core/manifest.toml`) declare
> `image_format = "RootfsErofs"` so a production EROFS run still emits
> the right shape. `cargo xtask images build-all` overrides the
> in-tree value to `RootfsInitramfsCpio` for the dev pipeline only.

---

## Section 5 — Stage a Linux guest kernel binary

The AVF substrate boots the guest with `vmlinux` from
`$RAXIS_INSTALL_DIR/kernel/`. `cargo xtask images dev-kernel` resolves
either a local file or a URL (with mandatory SHA-256 verification) and
atomically writes the binary to the canonical layout.

If you already have a compatible `vmlinux` for `aarch64`:

```bash
cargo xtask images dev-kernel --from-file /path/to/vmlinux-aarch64-virt
```

### §5.1 — Required kernel `CONFIG_*` flags (READ BEFORE choosing a kernel)

AVF advertises every virtio device — block, console, vsock, network,
and filesystem — over **virtio-pci**, never via virtio-mmio. The guest
kernel MUST enumerate them through the PCI bus or the boot dies
silently the moment `unpack_to_rootfs` finishes (AVF reports
`startWithCompletionHandler:` success, the console FIFO closes without
emitting a single byte, and every `connect_vsock` from the host
returns `ECONNRESET`). The substrate's symptom suite is:

```text
{"event":"avf_vm_started","vcpu":1,"mem_mib":1024}
{"event":"avf_console_pump_eof","path":"…/console.log"}
isolation spawn failed: transport fault: apple-vz-14.x: vsock CONNECT 1024: \
  AVF connect_vsock did not succeed within 30s; \
  last guest-side error: The operation couldn't be completed. \
  Connection reset by peer
```

A guest kernel intended for the AVF substrate MUST be built with at
least the following config flags `=y`:

| Flag                                  | Why                                                  |
|---------------------------------------|------------------------------------------------------|
| `CONFIG_VIRTIO_PCI`                   | AVF advertises virtio devices on the PCI bus.        |
| `CONFIG_VIRTIO_BLK`                   | Rootfs as virtio-blk drive (`RootfsErofs` path).     |
| `CONFIG_VIRTIO_NET`                   | Historically required for the deleted `EgressTier::Tier1Tproxy` NAT bridge. After the Tier1Tproxy deletion the kernel emits no virtio-net device for any shipped tier (`Mediated` / `None`); leaving the config option compiled in is harmless. |
| `CONFIG_VIRTIO_CONSOLE`               | `console=hvc0` lines reach the host console-log.     |
| `CONFIG_VIRTIO_VSOCKETS`              | Kernel↔planner control channel (port 1024).         |
| `CONFIG_VSOCKETS`                     | Guest userspace `AF_VSOCK` socket support.           |
| `CONFIG_FUSE_FS` + `CONFIG_VIRTIO_FS` | Workspace + meta-sidecar shares (`/workspace`, `/raxis-meta`). |
| `CONFIG_BLK_DEV_INITRD`               | Initramfs `RootfsInitramfsCpio` path (the dev pipeline). |
| `CONFIG_TMPFS`                        | The unpacker mounts the cpio.gz contents into a tmpfs rootfs. |

**Firecracker reference kernels (the docs/getting-started kernels)
DO NOT satisfy this list.** They ship with `CONFIG_VIRTIO_MMIO=y` and
no `CONFIG_VIRTIO_PCI`, `CONFIG_FUSE_FS`, or `CONFIG_VIRTIO_FS`. The
guest boots, fails to enumerate any virtio device because the AVF
bus advertises them on PCI, hangs without producing console output,
and AVF tears the VM down. **Do NOT use Firecracker reference kernels
with this substrate.** The earlier revision of this doc recommended
them; that recommendation was a regression and has been removed.

Acceptable hermetic sources for an AVF-compatible aarch64 vmlinux:

1. **Apple's recommended Fedora pxeboot kernel** — the kernel Apple's
   own AVF sample code reference for Linux guests. Available at
   `https://download.fedoraproject.org/pub/fedora/linux/releases/<rel>/Everything/aarch64/os/images/pxeboot/vmlinuz`.
   Note that recent Fedora releases (≥ 38) ship the kernel in EFI
   `zboot` wrapper format (PE32+ executable, zstd-compressed payload);
   the `VZLinuxBootLoader` direct-kernel path requires the
   uncompressed Image, so you must extract the inner kernel via
   `Documentation/admin-guide/kernel-parameters/extract-vmlinux` or
   boot via `VZEFIBootLoader` instead (V2 ships only `VZLinuxBootLoader`).

2. **A custom kernel built from upstream Linux** with the config
   above. The Cloud Hypervisor reference defconfig
   (`https://github.com/cloud-hypervisor/linux/blob/ch-6.12.8/arch/arm64/configs/ch_defconfig`)
   covers every flag in the table; the resulting `arch/arm64/boot/Image`
   is the canonical AVF-compatible kernel format.

3. **The historical kernel staged at
   `~/.raxis-install/kernel/vmlinux`** if you have an existing
   "working e2e" install on this host — that kernel was built against
   the AVF spec and is preserved across re-installs (the
   `--install-dir` flag on `dev-kernel` does not touch the user's
   default $HOME copy).

If the kernel you stage trips the symptom suite above, run

```bash
file "$RAXIS_INSTALL_DIR/kernel/vmlinux"
strings "$RAXIS_INSTALL_DIR/kernel/vmlinux" | rg "CONFIG_VIRTIO_(PCI|MMIO|FS)" | head
```

If `strings` shows `CONFIG_VIRTIO_MMIO=y` and the PCI / FUSE flags are
absent, the kernel is Firecracker-targeted and will not work — re-stage
from one of the three sources above.

If you do not yet have a kernel and need a working hermetic default,
the Fedora pxeboot kernel is the path Apple's own AVF sample code
takes:

```bash
# Pin a known-good Fedora ARM64 vmlinuz; the `--sha256` flag is
# mandatory and the subcommand refuses to install on mismatch.
cargo xtask images dev-kernel \
    --url    "https://mirrors.kernel.org/fedora/releases/<rel>/Everything/aarch64/os/images/pxeboot/vmlinuz" \
    --sha256 "<hex sha256 of the file>"
```

Verify:

```bash
ls -la "$RAXIS_INSTALL_DIR/kernel/vmlinux"
shasum -a 256 "$RAXIS_INSTALL_DIR/kernel/vmlinux"
```

---

## Section 6 — Code-sign `raxis-kernel` against the AVF entitlements

Apple's Virtualization.framework refuses to construct a
`VZVirtualMachine` from a binary that is not codesigned with both the
hypervisor and virtualization entitlements; every AVF API returns
`-67050 (errSecInternalError)` before any RAXIS code runs.

For local development, ad-hoc signing (`--sign -`) is sufficient:

```bash
cargo xtask dev-codesign                        # signs target/release/raxis-kernel
                                                 # against release/raxis.entitlements

# Confirm the signature carries the four entitlements.
codesign --display --entitlements - target/release/raxis-kernel
# Should list:
#   com.apple.security.hypervisor       true
#   com.apple.security.virtualization   true
#   com.apple.security.network.client   true
#   com.apple.security.network.server   true
```

> Production builds use a Developer-ID identity and notarization (see
> [`raxis/specs/v2/release-and-distribution.md §6.3`](../specs/v2/release-and-distribution.md)). `dev-codesign`
> is the dev-host shortcut.

---

## Section 7 — Run the V1 demo on top of the V2 substrate

You now have the AVF substrate fully wired: dev trust anchor live in
the kernel build, signed canonical images under
`$RAXIS_INSTALL_DIR/images/`, a guest kernel under
`$RAXIS_INSTALL_DIR/kernel/`, and an AVF-entitled host binary.

The rest of the demo flow is identical to [the V1 walkthrough](./README.md):

```bash
# Step 7a — operator key + clean data dir.
mkdir -p "$HOME/raxis-keys"
openssl genpkey -algorithm ED25519 -out "$HOME/raxis-keys/operator_private.pem"
openssl pkey    -in   "$HOME/raxis-keys/operator_private.pem" \
                -pubout -out "$HOME/raxis-keys/operator_public.pem"
chmod 600 "$HOME/raxis-keys/operator_private.pem"

export RAXIS_DATA_DIR="$HOME/.raxis-demo"
rm -rf "$RAXIS_DATA_DIR"
export RAXIS_OPERATOR_KEY="$HOME/raxis-keys/operator_private.pem"

# Step 7b — genesis ceremony (writes policy.toml + per-kernel keys).
target/release/raxis genesis \
    --operator-key  "$HOME/raxis-keys/operator_private.pem" \
    --operator-name "Chika"

# Step 7c — start the kernel daemon. Leave running in a dedicated
#           terminal so its stderr is visible.
RAXIS_INSTALL_DIR="$HOME/.raxis-demo-install" \
RAXIS_DATA_DIR="$RAXIS_DATA_DIR" \
target/release/raxis-kernel

# Step 7d — preflight from a second terminal.
target/release/raxis status
target/release/raxis doctor
```

The expected stderr at boot includes a `canonical_image_kind_resolved`
line per role (proving the kernel read the
`image_format = RootfsInitramfsCpio` declaration from the signed
manifest), plus `linux_kernel_binary_present` from the boot-time
preflight.

From here, every CLI write command (plan submit, plan approve, session
create, etc.) drives the production code path — the only differences
from production are (a) the substrate is AVF (you can see the guest VM
in `$ vmstat`), (b) the canonical images are dev-built initramfs blobs
instead of EROFS, and (c) the kernel signature is ad-hoc rather than
notarized.

---

## Section 8 — Where each piece is implemented

| Step | Crate / file | Spec reference |
|---|---|---|
| §0 dev-prereqs | `xtask/src/dev_prereqs.rs` | `demo-e2e-sample/AVF_DEMO.md §0` |
| §1 dev-keys | `xtask/src/dev_keys.rs` | `release-and-distribution.md §8` |
| §3 dev-stage | `xtask/src/images.rs` | `planner-harness.md §14.4` |
| §4 build-all | `xtask/src/images.rs` + `crates/initramfs-builder/` + `crates/image-builder/` | `e2e-live-test-gap.md §3 (a)` |
| §4 image_format | `crates/image-manifest/src/lib.rs` (`SCHEMA_VERSION = 3`) | `extensibility-traits.md §3.4.1` |
| §5 dev-kernel | `xtask/src/dev_kernel.rs` | `system-requirements.md §11` |
| §6 dev-codesign | `xtask/src/dev_codesign.rs` + `release/raxis.entitlements` | `system-requirements.md §5.2` |
| §7 manifest verification | `crates/canonical-images/src/lib.rs::read_verified_image_format` | `kernel-core.md §canonical-image-trust` |
| §7 boot preflight | `kernel/src/canonical_images_preflight.rs` (`probe_linux_kernel_binary_at_boot` + `resolve_image_kind_for_role`) | `kernel-core.md §boot-sequence` |
| AVF runtime | `crates/isolation-apple-vz/src/{config,runtime}.rs` | `extensibility-traits.md §3.4` |
| Vsock transport | `crates/planner-core/src/transport.rs` (under the `vsock-transport` Cargo feature) | `peripherals.md §3` |

---

## Tear-down

In the kernel terminal: **`Ctrl-C`** (clean SIGINT — kernel emits
`KernelStopped` and exits 0). Then:

```bash
rm -rf "$RAXIS_DATA_DIR" "$RAXIS_INSTALL_DIR"
# Optional — also drop the dev signing key and re-mint next time.
rm -rf "$HOME/.config/raxis/keys"
```

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `error: linker 'aarch64-linux-musl-gcc' not found` | musl linker missing | Run `cargo xtask dev-prereqs --install` (see §0); manual fallback: `brew install filosottile/musl-cross/musl-cross` plus the `[target.aarch64-unknown-linux-musl]` snippet in `~/.cargo/config.toml` |
| `error: target 'aarch64-unknown-linux-musl' not installed` | rustup target not added | `rustup target add aarch64-unknown-linux-musl` |
| `Failed to parse entitlements: AMFIUnserializeXML: syntax error` from `dev-codesign` | `release/raxis.entitlements` was edited and now contains XML comments inside `<dict>` (AMFI rejects them) | Keep all comments OUTSIDE the `<dict>` element (above the `<plist>` open tag). The repo file is structured this way intentionally. |
| `errSecInternalError (-67050)` at AVF startup | Kernel binary not codesigned, or signed without entitlements | Re-run `cargo xtask dev-codesign`; verify with `codesign --display --entitlements -` |
| `KernelPathMissing` at session spawn | `$RAXIS_INSTALL_DIR/kernel/vmlinux` absent | Run §5 (`cargo xtask images dev-kernel`) |
| `manifest signature does not verify` at boot | `RAXIS_KERNEL_SIGNING_KEY_HEX` not exported when `cargo build` ran | Re-`cargo build --release -p raxis-kernel` with the env var live (§2). The kernel's trust anchor is build-pinned. |
| `canonical image not found` at boot | `cargo xtask images build-all` not run, or `RAXIS_INSTALL_DIR` mismatched | Re-run §4 with the same `RAXIS_INSTALL_DIR` value used in §7 |
| `avf_vm_started` immediately followed by `avf_console_pump_eof` and a `vsock CONNECT 1024 … Connection reset by peer` failure | Kernel at `$RAXIS_INSTALL_DIR/kernel/vmlinux` does not have `CONFIG_VIRTIO_PCI` / `CONFIG_VIRTIO_FS` / `CONFIG_FUSE_FS` compiled in — typically because it is a Firecracker reference kernel. AVF advertises virtio over PCI; the guest enumerates nothing on the MMIO bus, the console never receives any printk, and the VM exits before binding `AF_VSOCK`. | Re-stage a kernel built per §5.1 (Apple's recommended Fedora pxeboot kernel, a Cloud Hypervisor `ch_defconfig`-built upstream kernel, or restore from `~/.raxis-install/kernel/vmlinux` if you have a historical working install). |
| `Kernel panic - not syncing: VFS: Unable to mount root fs on unknown-block(0,0)` in the guest console.log, immediately after `tmpfs: incomplete write (-28 != …)` | Executor-starter VM was spawned with too little memory; the initramfs unpacker ran out of tmpfs budget partway through `unpack_to_rootfs`. The ~560 MiB dev-host cpio.gz needs ≥ 6 GiB to unpack cleanly. | The kernel-internal default (`ExecutorSpawnContext::executor_mem_mib`) is 6 GiB as of `host-capacity.md §5.1`. If a plan overrode `vm_memory_mb` to a smaller value, restore the per-task default or pin a production EROFS image (which skips the unpacker entirely). |

---

## Cross-references

- [`raxis/specs/v2/extensibility-traits.md §3.4`](../specs/v2/extensibility-traits.md) — `VmSpec.linux_kernel_path` + the architectural decision keeping rootfs on `VerifiedImage.body`.
- [`raxis/specs/v2/planner-harness.md §14.4`](../specs/v2/planner-harness.md) — production EROFS image-build pipeline (this demo is the macOS-hermetic dev companion).
- [`raxis/specs/v2/e2e-live-test-gap.md`](../specs/v2/e2e-live-test-gap.md) — gaps the demo closes (mkfs.erofs-on-macOS, image_format declaration, host trust anchor).
- [`raxis/specs/v2/release-and-distribution.md §6.3 + §8`](../specs/v2/release-and-distribution.md) — entitlements, dev-keys layout.
- [`raxis/specs/v2/system-requirements.md §5.2 + §11`](../specs/v2/system-requirements.md) — codesign + kernel binary install layout.
- [`raxis/kernel/tests/full_e2e_session_lifecycle.rs`](../kernel/tests/full_e2e_session_lifecycle.rs) — the docker-gated full E2E (real Anthropic + Postgres + MongoDB).
- [`raxis/live-e2e/src/slice_session_spawn.rs`](../live-e2e/src/slice_session_spawn.rs) — the Subprocess-substrate session-spawn slice (no AVF, no docker; the smallest "real wire-bytes" slice that works hermetically on macOS).
