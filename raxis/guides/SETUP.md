# RAXIS Setup

Use this page for the shortest current path from a clean checkout to a
bootable local install.

## 0. One-Shot Source Setup

For a fresh development/e2e host, prefer the one-shot wrapper. It
runs the host prereq checks, builds the release host tools, builds the
dashboard, bakes guest images, rebuilds `raxis-kernel` with the same
image-signing trust anchor, verifies that trust anchor, and ad-hoc
codesigns the kernel on macOS.

```bash
cd /path/to/raxis/raxis
export RAXIS_INSTALL_DIR="$HOME/.raxis-install"

cargo xtask source-setup \
  --install-dir "$RAXIS_INSTALL_DIR" \
  --kernel-from-file /path/to/vmlinux \
  --kernel-config /path/to/vmlinux.config \
  --no-cache
```

Pinned prebuilt kernel variant:

```bash
cargo xtask source-setup \
  --install-dir "$RAXIS_INSTALL_DIR" \
  --kernel-url https://example.com/vmlinux-aarch64 \
  --kernel-sha256 <64-hex-digest> \
  --kernel-config /path/to/vmlinux.config
```

Use `--dry-run` first to print the plan without changing the host.
Add `--with-observability` when you also want the local OTel,
Prometheus, and Grafana stack started.

| Phase | First-run expectation | What is happening |
|---|---:|---|
| Host prereqs | 2-20 min | Installs/verifies Rust musl target, OpenSSL 3, linker config, AVF codesign/firewall on macOS, or KVM/vsock/cgroup checks on Linux. |
| Host tools | 3-15 min | Builds `raxis-cli`, `raxis-gateway`, `raxis-otel-pusher`, and `raxis-supervisor` in release mode. |
| Dashboard | 1-6 min | Runs `npm ci` and `npm run build` in `dashboard-fe/`. |
| Prebuilt guest kernel | 1-10 min when `--kernel-url` is used | Downloads pinned `vmlinux`, checks SHA-256, validates the nftables config, and stages the sidecar. |
| Guest image bake | 10-45 min with `--no-cache` | Validates/stages `vmlinux`, checks its nftables `.config`, pulls/builds rootfs layers, cross-compiles guest binaries, packs and signs initramfs images. |
| Host kernel | 2-10 min | Rebuilds `raxis-kernel` with the bake's public trust anchor. |
| Verify/sign | under 1 min | Verifies the embedded trust anchor and codesigns the AVF kernel binary on macOS. |

The wrapper exists because these were the easy-to-miss setup hurdles:

- The guest Linux kernel is separate from the role images. It must be
  staged as `<install_dir>/kernel/vmlinux`, and its config must include
  the nftables/netfilter symbols in
  `images/kernel/raxis-guest-a3-netfilter.config`.
- `cargo xtask images bake` mints or reuses a per-clone image-signing
  key under `.git/info/raxis-signing-key/`. The host `raxis-kernel`
  must then be rebuilt with the matching public key and verified.
- macOS AVF requires the kernel binary to be codesigned with
  `release/raxis.entitlements`, and the firewall allowlist avoids the
  recurring incoming-connection prompt.
- Docker, Podman, or Buildah can be quiet during base-image pulls,
  package-manager work, export, tar extraction, and large cpio packing.
  The bake now emits structured `bake_progress` and
  `bake_role_progress` lines before those long phases.
- Live e2e source-tree runs auto-build the latest release
  `raxis-gateway` before policy injection, so operators do not need
  to export `RAXIS_GATEWAY_BINARY` or risk pointing at stale gateway
  bits. Set `RAXIS_E2E_SKIP_GATEWAY_AUTO_BUILD=1` only for packaged
  binary validation.
- A user-writable `RAXIS_INSTALL_DIR` is easier for development than
  `/usr/local/lib/raxis`, which may require elevated permissions.

The remaining sections show the same flow by hand for operators who
want to inspect or repeat individual phases.

## Fast Local Builds

The workspace keeps release builds production-shaped, but local
`cargo build` and `cargo test` use lighter debug information:

- `profile.dev` and `profile.test` emit line tables instead of full
  variable debuginfo, so panic backtraces still point at source lines.
- Build scripts and proc-macros compile without debuginfo; this is a
  common hot path in large Rust workspaces and does not change the code
  being tested.
- Incremental compilation stays enabled for dev/test profiles.

Optional machine-local accelerators are safe but intentionally not
checked into `.cargo/config.toml`:

```bash
# Optional: cache rustc outputs across clean rebuilds and role bakes.
brew install sccache        # macOS
# or your distro package manager on Linux
export RUSTC_WRAPPER=sccache
sccache --show-stats
```

Do not replace validation commands with `cargo check` when correctness
matters. Use `cargo check` for fast edit feedback, then run the same
`cargo test`, image bake, and live-e2e commands you intend to release.

## 1. Host Prereqs

Source builds require:

| Surface | Requirement |
|---|---|
| Rust workspace | Current stable Rust, Cargo, Git 2.30+, C/C++ toolchain, `make`, `pkg-config` |
| Operator keys | OpenSSL 3 CLI for Ed25519 PEM generation |
| Guest images | Docker, Podman, or Buildah when baking rootfs-producing image roles |
| Dashboard UI | Node.js 20+ and npm |
| Local observability stack | Docker Compose for OTel Collector, Prometheus, and Grafana |

macOS:

```bash
cargo xtask dev-prereqs --install
```

Linux:

```bash
cargo xtask linux-prereqs
```

Both commands are idempotent. macOS installs/verifies the musl target,
OpenSSL 3, linker config, codesign, and the firewall allowlist. Linux
checks KVM, vhost-vsock, cgroup v2, and Firecracker tooling.

## 2. Build Host Tools

First prove the workspace builds with the checked-in lockfile:

```bash
cargo build --workspace --locked
```

Build the host binaries:

```bash
cargo build --release --locked \
  -p raxis-cli \
  -p raxis-kernel \
  -p raxis-gateway \
  -p raxis-otel-pusher \
  -p raxis-supervisor
```

Install the operator-facing tools if you want them on `$PATH`:

```bash
cargo install --path cli --locked --force
cargo install --path gateway --locked --force
cargo install --path pusher --locked --force
cargo install --path crates/supervisor --bin raxis-supervisor --locked --force
```

Build or install the host `raxis-kernel` daemon after the image bake,
so it can embed the same manifest-signing trust anchor as the images
you staged.

Build the dashboard frontend when you plan to serve the dashboard UI:

```bash
cd dashboard-fe
npm ci
npm run build
cd ..
```

## 3. Bake Guest Images

Use the single image command:

```bash
export RAXIS_INSTALL_DIR="$HOME/.raxis-install"
cargo xtask images bake --kernel-from-file /path/to/vmlinux --kernel-config /path/to/vmlinux.config
```

The guest kernel must include the nftables/netfilter options in
`images/kernel/raxis-guest-a3-netfilter.config`.

Rebuild the host daemon with the matching trust anchor and verify the
bytes you will run:

```bash
RAXIS_KERNEL_SIGNING_KEY_HEX="$(cat .git/info/raxis-signing-key/pk.hex)" \
  cargo build --release --locked -p raxis-kernel
cargo xtask images verify-trust-anchor --kernel target/release/raxis-kernel
```

On macOS development hosts, sign that release binary for AVF:

```bash
cargo xtask dev-codesign --profile release
```

## 4. Create Operator Key

```bash
mkdir -p "$HOME/raxis-keys"
openssl genpkey -algorithm ED25519 -out "$HOME/raxis-keys/operator_private.pem"
chmod 600 "$HOME/raxis-keys/operator_private.pem"
export RAXIS_OPERATOR_KEY="$HOME/raxis-keys/operator_private.pem"
```

Use Homebrew `openssl@3` on macOS; LibreSSL cannot generate Ed25519
keys.

## 5. Scaffold the Data Dir

Interactive:

```bash
export RAXIS_DATA_DIR="$HOME/.raxis-demo"
raxis setup --interactive
```

Scripted:

```bash
raxis setup \
  --operator-name "$USER" \
  --provider anthropic \
  --provider-id anthropic-default
```

`setup` writes a starter policy and starter plan, then prints the
remaining commands. It does not run genesis for you because genesis
touches operator key material.

## 6. Run Genesis

```bash
raxis genesis --operator-name "$USER"
```

This uses `RAXIS_OPERATOR_KEY`. Equivalent explicit form:

```bash
raxis genesis --operator-key "$RAXIS_OPERATOR_KEY" --operator-name "$USER"
```

Air-gapped operators can mint a cert offline and pass it instead:

```bash
raxis genesis --operator-cert operator.cert.toml
```

## 7. Edit and Sign Policy

Edit:

```text
$RAXIS_DATA_DIR/policy/policy.toml
```

Fill in the provider, VM image aliases/digests, allowed worktree roots,
and egress allowlist for your environment. Then sign:

```bash
raxis policy sign "$RAXIS_DATA_DIR/policy/policy.toml" --key "$RAXIS_OPERATOR_KEY"
```

## 8. Add Provider Credential

```bash
raxis credential add anthropic-api-key --file ./anthropic-key.txt
```

Use the credential name referenced by your policy.

## 9. Verify and Start

```bash
raxis doctor --data-dir "$RAXIS_DATA_DIR"
RAXIS_DATA_DIR="$RAXIS_DATA_DIR" target/release/raxis-kernel
```

Submit the starter plan from another shell:

```bash
raxis submit plan "$RAXIS_DATA_DIR/plan/plan.toml" --no-dry-run
```

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| `ERR_ALREADY_INITIALIZED` | You already ran genesis for this data dir. Pick a new data dir or use `--force` only for throwaway dev state. |
| `trust_anchor_unpopulated` | Run `cargo xtask source-setup` or the manual sequence: `images bake`, rebuild `raxis-kernel` with `RAXIS_KERNEL_SIGNING_KEY_HEX="$(cat .git/info/raxis-signing-key/pk.hex)"`, then `images verify-trust-anchor`. |
| guest VM cannot install nftables rules | Stage a guest kernel whose `.config` includes `images/kernel/raxis-guest-a3-netfilter.config`, then run `cargo xtask source-setup --no-cache` or `cargo xtask images bake --no-cache` so rootfs outputs and the staged kernel are validated together. |
| setup says a command is deferred | Run the printed command manually; setup is a scaffold, not a key-custody automation. |
