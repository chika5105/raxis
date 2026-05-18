# RAXIS Setup

Use this page for the shortest current path from a clean checkout to a
bootable local install.

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
npm install
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
| `trust_anchor_unpopulated` | Run `cargo xtask images bake`, rebuild `raxis-kernel` with `RAXIS_KERNEL_SIGNING_KEY_HEX="$(cat .git/info/raxis-signing-key/pk.hex)"`, then `images verify-trust-anchor`. |
| guest VM cannot install `iptables-nft` rules | Rebuild/stage a guest kernel with `images/kernel/raxis-guest-a3-netfilter.config`. |
| setup says a command is deferred | Run the printed command manually; setup is a scaffold, not a key-custody automation. |
