# 01 · Prerequisites

> **Goal.** End this page with `raxis doctor` printing all-green.

RAXIS needs a Rust toolchain, an Ed25519-capable OpenSSL, and a
hypervisor backend. The workspace ships a one-shot `cargo xtask`
command that installs (or verifies) everything else.

---

## OS matrix

| Platform                               | Substrate                            | Hypervisor                      | Required kernel             |
| -------------------------------------- | ------------------------------------ | ------------------------------- | --------------------------- |
| **macOS 13+** (Apple Silicon or Intel) | Apple Virtualization framework (AVF) | built-in                        | n/a                         |
| **Linux 5.10+** with KVM               | Firecracker microVMs                 | `/dev/kvm`, user in `kvm` group | guest kernel ≥ 5.14 (in-VM) |
| Windows / WSL                          | —                                    | —                               | not supported in V2         |

The substrate is auto-detected at kernel startup. If neither AVF nor
KVM is available the kernel refuses to boot with
`BOOT_ERR_ISOLATION_UNAVAILABLE`. The
`RAXIS_UNSAFE_FALLBACK_ISOLATION` env var unlocks a subprocess fallback
for tests only — never set it on a host that runs untrusted agents.

---

## What you need, regardless of OS

| Tool          | Purpose                           | Verify                                                     |
| ------------- | --------------------------------- | ---------------------------------------------------------- |
| Rust stable   | Build the workspace               | `cargo --version`                                          |
| `openssl` 3.x | Mint the operator Ed25519 keypair | `openssl version` (must say `OpenSSL 3.x`, not `LibreSSL`) |
| `git` ≥ 2.30  | Repo operations and worktrees     | `git --version`                                            |
| `uuidgen`     | Lineage IDs in some scripts       | `uuidgen`                                                  |
| `jq`          | Parse `--json` output in examples | `jq --version`                                             |

On macOS the default `/usr/bin/openssl` is LibreSSL, which cannot
generate Ed25519 keys. Install Homebrew `openssl@3` and put its `bin/`
on `$PATH`:

```bash
brew install openssl@3
# Apple Silicon:
export PATH="/opt/homebrew/opt/openssl@3/bin:$PATH"
# Intel macOS:
export PATH="/usr/local/opt/openssl@3/bin:$PATH"
```

---

## macOS — one command for everything else

The AVF substrate needs a musl cross-compiler, the
`<arch>-unknown-linux-musl` Rust target, the Xcode CLT `codesign`, and
a `[target...] linker` pin in your Cargo config. The workspace ships
this as a single subcommand that is idempotent on every re-run.

```bash
cd /path/to/raxis     # workspace root

# Verify-only — exits non-zero on the first missing piece.
cargo xtask dev-prereqs

# Verify + install missing brew packages and rustup targets.
cargo xtask dev-prereqs --install
```

What `dev-prereqs --install` does (in order):

1. **Homebrew probe** — refuses to continue if `brew` is not on `$PATH`.
2. **Brew packages** — installs `filosottile/musl-cross/musl-cross` and
   `openssl@3` if missing.
3. **Rustup target** — adds `<host-arch>-unknown-linux-musl`.
4. **Cargo linker config** — patches `~/.cargo/config.toml` (or the
   workspace `.cargo/config.toml` with `--scope workspace`) with the
   `[target.<arch>-unknown-linux-musl] linker = "..."` pin. Existing
   values are preserved verbatim.
5. **`codesign` probe** — required for ad-hoc-signing the kernel
   binary against the AVF entitlements (`release/raxis.entitlements`).
6. **Cargo probe** — verifies the toolchain.
7. **macOS Application Firewall allowlist** — allowlists the raxis
   host binaries (`raxis-kernel`, `raxis-otel-pusher`,
   `raxis-live-e2e`) via `sudo socketfilterfw --add` so the recurring
   "allow `raxis-kernel` to accept incoming network connections"
   popup does not re-appear on every fresh `cargo build`. Prompts
   for `sudo` exactly once; auto-skipped when the firewall is
   disabled. Pass `--skip-firewall` on managed devices that disallow
   `sudo`. See
   [`recipes/setup/11-macos-firewall-popup.md`](../recipes/setup/11-macos-firewall-popup.md)
   for the full recipe and
   [`xtask/src/macos_firewall.rs`](../../xtask/src/macos_firewall.rs)
   for the inventory of managed binaries.

Each step emits one JSON line so you can grep for the first failure.

Reference: [`xtask/src/dev_prereqs.rs`](../../xtask/src/dev_prereqs.rs)
and [`demo-e2e-sample/AVF_DEMO.md §0`](../../demo-e2e-sample/AVF_DEMO.md).

### macOS — code-sign the kernel against AVF entitlements

`raxis-kernel` needs Apple's
`com.apple.developer.virtualization`-family entitlements to use AVF.
The workspace provides:

```bash
cargo build --release -p raxis-kernel -p raxis-cli -p raxis-gateway
cargo xtask dev-codesign --profile release
```

`dev-codesign` ad-hoc-signs `target/release/raxis-kernel` against
[`release/raxis.entitlements`](../../release/raxis.entitlements). On
Linux it is a no-op. Reference:
[`specs/v2/system-requirements.md §5.2`](../../specs/v2/system-requirements.md)
and [`specs/v2/release-and-distribution.md §6.3`](../../specs/v2/release-and-distribution.md).

---

## Linux — one command for the host substrate

The Firecracker substrate needs `/dev/kvm` reachable as your user,
`vhost_vsock` loaded, cgroup v2 mounted, and the `firecracker(1)`
binary on `$PATH`. The workspace ships a host preflight as an `xtask`:

```bash
cd /path/to/raxis

cargo xtask linux-prereqs              # human-readable report
cargo xtask linux-prereqs --json       # machine-readable, same checks
```

What it verifies:

| Check                                                          | Outcome on miss                                       |
| -------------------------------------------------------------- | ----------------------------------------------------- |
| `linux.kernel_version` ≥ 5.10                                  | **Fail** — upgrade kernel                             |
| `/dev/kvm` exists and is openable                              | **Fail** — install KVM, add user to `kvm` group       |
| User's groups include `kvm`                                    | **Fail** — `sudo usermod -aG kvm $USER && newgrp kvm` |
| `vhost_vsock` module loaded                                    | **Fail** — `sudo modprobe vhost_vsock`                |
| cgroup v2 mounted (`/sys/fs/cgroup/cgroup.controllers` exists) | **Fail** — Linux ≥ 5.14 systemd defaults              |
| `firecracker(1)` on `$PATH`                                    | **Warn** — install before first kernel boot           |
| `virtiofsd(1)` on `$PATH`                                      | **Warn** — V3 prereq, not blocking V2                 |

Exit codes mirror `raxis doctor`: `0` = all OK, `1` = any warn, `2` =
any fail. Reference: [`xtask/src/linux_prereqs.rs`](../../xtask/src/linux_prereqs.rs)
and [`specs/v2/isolation-linux-microvm.md §9`](../../specs/v2/isolation-linux-microvm.md).

### Linux — one-shot Firecracker image bundle

After the prereqs are green you can stage a reference guest kernel and
the canonical role initramfs blobs with a single command. Pin a SHA so
the kernel binary cannot drift on you mid-demo.

```bash
cargo xtask linux-microvm bundle \
  --install-dir ~/.local/share/raxis \
  --kernel-url https://example.com/vmlinux-aarch64 \
  --kernel-sha256 <hex-digest>
```

Reference:
[`xtask/src/linux_microvm.rs`](../../xtask/src/linux_microvm.rs).

---

## Verify the install

Once `cargo xtask dev-prereqs` (macOS) or `cargo xtask linux-prereqs`
(Linux) is green, install the three binaries:

```bash
cd /path/to/raxis        # workspace root
cargo install --path cli      --locked --force
cargo install --path kernel   --locked --force
cargo install --path gateway  --locked --force
```

Confirm:

```bash
which raxis raxis-kernel raxis-gateway
raxis --help | head -20
```

Now flip to [`02-first-initiative.md`](02-first-initiative.md) and run
your first plan. (`raxis doctor` ties the host check together but is
most useful once a `RAXIS_DATA_DIR` exists — you'll run it again at the
end of page 02.)

---

## Cross-references

- [`xtask/src/dev_prereqs.rs`](../../xtask/src/dev_prereqs.rs) — the
  authoritative list of what `dev-prereqs` installs and probes.
- [`xtask/src/linux_prereqs.rs`](../../xtask/src/linux_prereqs.rs) — the
  authoritative list of Linux KVM / vsock / cgroup checks.
- [`specs/v2/system-requirements.md`](../../specs/v2/system-requirements.md) —
  full host + VM kernel requirements matrix.
- [`specs/v2/isolation-platform-parity.md`](../../specs/v2/isolation-platform-parity.md) —
  side-by-side Apple-VZ vs Firecracker behaviour.
- [`SETUP.md`](../SETUP.md) — the manual long-form variant of this page,
  retained for operators who want to inspect every step by hand.
