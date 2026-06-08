# 01 · Install and Verify

> **Goal.** End this page with the Homebrew-installed RAXIS runtime
> verified and ready for genesis.

This page is for an **operator or evaluator**. It assumes you want to
run RAXIS, not build it. If you are changing RAXIS source code, skip to
[`../SETUP.md`](../SETUP.md). If you are changing release packaging,
use [`../../release/README.md`](../../release/README.md).

Related setup entry points:

| Need | Start here |
|---|---|
| Fastest website-guided path from Homebrew to first initiative | [Website get-started flow](https://www.raxis.io/get-started) |
| Detailed Homebrew install and verification | This page |
| Source checkout, local builds, image baking, dashboard builds | [`../SETUP.md`](../SETUP.md) |

---

## Terms Before Commands

| Term | What you need to know now |
|---|---|
| `RAXIS_INSTALL_DIR` | Homebrew runtime bundle: `$(brew --prefix raxis)/share/raxis`. |
| `RAXIS_DATA_DIR` | Mutable kernel state. Use the Homebrew service path: `$(brew --prefix)/var/lib/raxis`. |
| `RAXIS_ENV` | Human-readable environment label. The Homebrew service defaults to `default`; non-default bootstrap runs can use `install.sh --env staging` to keep a separate data dir. |
| `RAXIS_OPERATOR_KEY` | Your private operator key. Exporting it is a convenience so signed requests do not need `--operator-key` every time. |
| Genesis | The one-time initialization that creates policy, keys, database, and the first audit record. |
| Policy | The signed rules the kernel enforces. |
| Provider | LLM provider config plus a credential file under `$RAXIS_DATA_DIR/providers/`. |
| Kernel | The authority process that admits plans and runs isolated agents. |
| Supervisor | The Homebrew service wrapper that keeps the kernel healthy. |
| Dashboard | Local UI at `http://127.0.0.1:9820`. |
| Managed repo | The repo RAXIS clones from and merges back into. Use the actual repo name as its id; keep branch names in `target_ref`. |
| Plan / initiative / task | A signed `plan.toml`, one admitted unit of work, and the executor/reviewer nodes inside it. |
| Orchestrator / executor / reviewer | Kernel-created coordinator, code-editing agent, and review agent. |
| Plan Builder | Visual `plan.toml` editor for the initiative DAG, task cards, model routing, tool profiles, credential setup, verifiers, kernel validation, copy, and download. |
| Policy Builder | Dashboard helper for policy discovery, TOML editing, kernel validation, and the signed epoch-advance path. |

The fastest path is to let the Homebrew helper run the safe defaults.
It uses POSIX `sh`, so the same command works from both zsh and bash.

## Fast Path: Homebrew

```bash
brew update
brew tap chika5105/raxis
brew install raxis

"$(brew --prefix raxis)/share/raxis/install.sh"
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

The helper runs genesis, prompts for your Anthropic key, writes the
provider credential with mode `0600`, signs policy, starts the Homebrew
service, and prints the exports you should keep for future shells.

Set the runtime bundle path in every shell that talks to this install:

```bash
export RAXIS_INSTALL_DIR="$(brew --prefix raxis)/share/raxis"
```

Use the Homebrew service data dir:

```bash
export RAXIS_DATA_DIR="$(brew --prefix)/var/lib/raxis"
export RAXIS_ENV="default"
```

That is the path `brew services start raxis` uses. Keep the same value
in every shell so foreground commands, the dashboard, and the daemon
all point at the same SQLite store, policy, audit chain, sockets, and
witness data. If you want a disposable rehearsal later, pass
`--data-dir <empty-dir>` to `install.sh`. If you want a named
environment with a separate Homebrew-style data dir, use:

```bash
"$(brew --prefix raxis)/share/raxis/install.sh" --env staging
```

That initializes `$(brew --prefix)/var/lib/raxis-staging` unless you
also pass `--data-dir`.

Verify the installed bundle:

```bash
command -v raxis
command -v raxis-kernel
raxis --version
raxis --help | head -20
raxis doctor signing-key-fp
raxis doctor canonical-images --install-dir "$RAXIS_INSTALL_DIR"
```

Expected: `command -v` points under your Homebrew prefix,
`raxis --version` prints the installed release, the help prints the CLI
usage, `signing-key-fp` says `trust anchor: populated`, and
`canonical-images` reports `worst: OK`.

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

## Homebrew Service Mode

Homebrew does not start RAXIS during install. After genesis and policy
signing, start it as a per-user launchd daemon:

```bash
brew services start raxis
brew services list | awk 'NR==1 || $1=="raxis"'
raxis-supervisor status
raxis doctor
```

The service uses:

```bash
RAXIS_INSTALL_DIR="$(brew --prefix raxis)/share/raxis"
RAXIS_DATA_DIR="$(brew --prefix)/var/lib/raxis"
RAXIS_ENV="default"
```

Expected: `brew services list` shows `raxis started`,
`raxis-supervisor status` reports `Healthy`, and `raxis doctor` reports
`worst: OK` after the kernel writes its first heartbeat.

Logs live at:

```bash
tail -f "$(brew --prefix)/var/log/raxis/kernel.log"
tail -f "$(brew --prefix)/var/log/raxis/kernel.err.log"
tail -f "$RAXIS_DATA_DIR/supervisor.stderr.log"
cat "$RAXIS_DATA_DIR/kernel_lifecycle_status.json"
```

Homebrew also wires launchd stdout/stderr to
`$(brew --prefix)/var/log/raxis/kernel.log` and
`$(brew --prefix)/var/log/raxis/kernel.err.log`, but most supervisor
decisions are written to `$RAXIS_DATA_DIR/supervisor.stderr.log`.

Stop the daemon with:

```bash
brew services stop raxis
```

`brew upgrade raxis` automatically restarts an active Homebrew service
after the upgraded bundle passes post-install checks, so the daemon does
not keep running the old Cellar binary. Stopped services stay stopped.
Skip one automatic restart during a maintenance window with:

```bash
RAXIS_BREW_AUTO_RESTART=0 brew upgrade raxis
```

Disable automatic upgrade restarts persistently with:

```bash
touch "$(brew --prefix)/etc/raxis/disable-brew-auto-restart"
```

By default this is a user LaunchAgent, not a privileged system daemon.
Do not also run `raxis-kernel` in a foreground terminal against the
same `RAXIS_DATA_DIR`; use one start mode at a time.

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
