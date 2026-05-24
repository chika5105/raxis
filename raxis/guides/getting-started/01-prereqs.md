# 01 · Install and Verify

> **Goal.** End this page with the Homebrew-installed RAXIS runtime
> verified and ready for genesis.

This page is for an **operator or evaluator**. It assumes you want to
run RAXIS, not build it. If you are changing RAXIS source code, skip to
[`../SETUP.md`](../SETUP.md). If you are changing release packaging,
use [`../../release/README.md`](../../release/README.md).

---

## Fast Path: Homebrew

```bash
brew update
brew tap chika5105/raxis
brew install raxis
```

Homebrew installs:

| Piece | Location |
|---|---|
| Operator CLI | `$(brew --prefix raxis)/bin/raxis` |
| Kernel daemon | `$(brew --prefix raxis)/bin/raxis-kernel` |
| Gateway and supervisor | `$(brew --prefix raxis)/bin/raxis-gateway`, `raxis-supervisor` |
| Dashboard static bundle | `$(brew --prefix raxis)/share/raxis/dashboard` |
| Canonical VM images | `$(brew --prefix raxis)/share/raxis/images` |
| Guest kernel | `$(brew --prefix raxis)/share/raxis/kernel/vmlinux` |

Set the runtime bundle path in every shell that starts the kernel:

```bash
export RAXIS_INSTALL_DIR="$(brew --prefix raxis)/share/raxis"
```

Use the default per-user data dir for the first run:

```bash
export RAXIS_DATA_DIR="$HOME/.raxis"
```

That is the path Homebrew prepares and the path the rest of this
getting-started guide uses. If you want a disposable rehearsal later,
set `RAXIS_DATA_DIR` to another empty directory before running
`raxis genesis`.

Verify the installed bundle:

```bash
command -v raxis
command -v raxis-kernel
raxis --help | head -20
raxis doctor signing-key-fp
raxis doctor canonical-images --install-dir "$RAXIS_INSTALL_DIR"
```

Expected: `command -v` points under your Homebrew prefix, the help
prints the CLI usage, `signing-key-fp` says `trust anchor: populated`,
and `canonical-images` reports `worst: OK`.

> If you run commands from inside a cloned source repo and see
> `permission denied: raxis`, your shell is trying to execute the local
> `./raxis` directory. Run `command -v raxis`; it should point at
> Homebrew, usually `/opt/homebrew/bin/raxis` on Apple Silicon.

---

## Host Requirements

| Platform | Supported substrate | Notes |
|---|---|---|
| **macOS 13+** on Apple Silicon or Intel | Apple Virtualization framework | Built into macOS. The Homebrew bottle ships notarized binaries. |
| **Linux 5.10+** with KVM | Firecracker microVMs | `/dev/kvm`, `vhost_vsock`, cgroup v2, and Firecracker must be available before first kernel boot. |
| Windows / WSL | Not supported in V2 | Use macOS or Linux for the reference implementation. |

Tools needed for the Homebrew first initiative:

| Tool | Purpose | Verify |
|---|---|---|
| Homebrew | Install RAXIS | `brew --version` |
| OpenSSL 3 | Mint your Ed25519 operator key | `openssl version` |
| Git | Canonical repo and worktrees | `git --version` |
| `jq` | Parse JSON examples | `jq --version` |

On macOS, `/usr/bin/openssl` is usually LibreSSL and cannot mint
Ed25519 keys. Use Homebrew OpenSSL 3:

```bash
brew install openssl@3 jq
export PATH="$(brew --prefix openssl@3)/bin:$PATH"
openssl version
```

Expected: `OpenSSL 3.x`.

Linux operators should install OpenSSL 3, Git, and `jq` through their
distribution package manager.

---

## Optional: Service Mode

For the first initiative, run `raxis-kernel` in a foreground terminal
so you can see the logs. After you have a real data dir and policy,
Homebrew can supervise the kernel:

```bash
brew services start raxis
brew services stop raxis
```

The service uses:

```bash
RAXIS_INSTALL_DIR="$(brew --prefix raxis)/share/raxis"
RAXIS_DATA_DIR="$(brew --prefix)/var/lib/raxis"
```

The getting-started guide uses `RAXIS_DATA_DIR="$HOME/.raxis"` instead,
because that matches the Homebrew post-install layout an end user sees.

---

## Source Builders

Do this only if you are developing RAXIS or validating a source
checkout. Source builds need Rust, native toolchains, Node.js, Docker
or Podman/Buildah for image baking, and platform-specific prereqs:

```bash
cd /path/to/raxis/raxis

# macOS source host
cargo xtask dev-prereqs --install

# Linux source host
cargo xtask linux-prereqs
```

Then follow [`../SETUP.md`](../SETUP.md), which covers host binary
builds, dashboard builds, guest image baking, trust-anchor embedding,
and macOS development codesigning.

---

## Next

Continue to [`02-first-initiative.md`](02-first-initiative.md). Keep
`RAXIS_INSTALL_DIR` and `RAXIS_DATA_DIR` exported in every terminal you
use for the run.
