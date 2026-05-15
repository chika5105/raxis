# RAXIS — One-Time Setup

> **Read this once, run the genesis ceremony once, then never again.**
> Every scenario under `scenarios/` assumes the host has been through
> this setup. If you are coming back to a machine that already has a
> RAXIS install, jump to the **"Confirming an existing install"**
> section.

This guide is the operationally-shortest path from a clean macOS or
Linux box to "kernel running, operator key in hand, ready to submit
a plan". It is the consolidated, modernized successor to
`raxis/demo-e2e-sample/README.md` Steps 1–7.

---

## Prerequisites

- **Rust toolchain** (stable; `rust-toolchain.toml` at the workspace
  root pins the channel automatically).
- **OpenSSL 3.x on `$PATH`.** macOS' default `/usr/bin/openssl` is
  LibreSSL and cannot generate Ed25519 keys. On macOS install
  Homebrew `openssl@3` and put its `bin/` first on `$PATH`. On Linux
  the distro's `openssl` package is typically already 3.x.
- **`git` ≥ 2.30** and **`uuidgen`** (preinstalled on macOS and most
  Linux distros).
- **A hypervisor for V2 isolation:**
  - Linux: KVM (`/dev/kvm`).
  - macOS: Apple Virtualization.framework (built-in on macOS 13+).
- **An LLM provider API key** for one of the supported providers
  (Anthropic by default).

Verify:

```bash
openssl version          # MUST show "OpenSSL 3.x", NOT "LibreSSL"
git --version
uuidgen
cargo --version
```

---

## Step 1 — Build and install the binaries

The workspace produces three binaries:

- `raxis` — operator CLI (crate name `raxis-cli`)
- `raxis-kernel` — long-lived daemon
- `raxis-gateway` — auto-spawned by the kernel; never run manually

```bash
cd /path/to/raxis        # the workspace root containing Cargo.toml
cargo install --path cli      --locked --force
cargo install --path kernel   --locked --force
cargo install --path gateway  --locked --force
```

Confirm the binaries land on `$PATH`:

```bash
which raxis raxis-kernel raxis-gateway
raxis --help | head -30
```

> **Faster development loop.** During iteration you can run the CLI
> and kernel from `cargo run -p raxis-cli -- <args>` and `cargo run
> -p raxis-kernel`. The gateway, however, **must** be reachable on
> `$PATH` because the kernel spawns it as a subprocess.

---

## Step 2 — Pick a data directory

The kernel keeps every byte of live state under `$RAXIS_DATA_DIR`
(defaults to `~/.raxis`). For demo / sandbox use, point it at a
throwaway location:

```bash
export RAXIS_DATA_DIR="$HOME/.raxis-demo"
```

Use the **same** `RAXIS_DATA_DIR` value in every shell that runs
`raxis*` binaries.

---

## Step 3 — Generate an operator keypair

```bash
mkdir -p "$HOME/raxis-keys"
cd "$HOME/raxis-keys"

openssl genpkey -algorithm ED25519 -out operator_private.pem
openssl pkey    -in operator_private.pem -pubout -out operator_public.pem

chmod 600 operator_private.pem
```

The example `operator_private.pem` at the workspace root is **example
material only** — generate your own.

---

## Step 4 — Run the genesis ceremony

> **This step runs exactly once per `RAXIS_DATA_DIR`.** Re-running it
> on an existing install fails with `genesis: refusing to overwrite
> existing data dir`. To force a fresh genesis on the same path,
> delete the data dir first (`rm -rf "$RAXIS_DATA_DIR"`) — irreversible.

```bash
raxis genesis \
  --operator-key  "$HOME/raxis-keys/operator_private.pem" \
  --operator-name "$USER"
```

What this does:

1. Generates the kernel's authority, quality, and verifier-token keys.
2. Mints a self-signed `OperatorCert` from your private key in-process
   (private bytes never persist under `$RAXIS_DATA_DIR`).
3. Writes `policy.toml` with the cert embedded under
   `[operators.entries.cert]`.
4. Installs the genesis row in `policy_epoch_history`.
5. Writes the chain-anchor `audit/segment-000.jsonl`.

Inspect:

```bash
ls "$RAXIS_DATA_DIR"
ls "$RAXIS_DATA_DIR/policy"
head -60 "$RAXIS_DATA_DIR/policy/policy.toml"
```

For air-gapped / production setups, mint the operator cert offline
with `raxis cert mint` on a machine that holds the private key, then
pass `--operator-cert <file>` to `raxis genesis`. See
[`specs/v1/cli-ceremony.md`](../specs/v1/cli-ceremony.md) §`genesis`.

---

## Step 5 — Configure your provider credentials

Each provider lives at
`$RAXIS_DATA_DIR/providers/<provider>.toml` with mode `0600` (the
kernel's `FileCredentialBackend` enforces this; a wrong mode is a
boot-time refusal).

Example for Anthropic:

```bash
mkdir -p "$RAXIS_DATA_DIR/providers"
cat > "$RAXIS_DATA_DIR/providers/anthropic-prod.toml" <<'EOF'
api_key = "sk-ant-REPLACE_ME"
EOF
chmod 600 "$RAXIS_DATA_DIR/providers/anthropic-prod.toml"
```

The matching `policy.toml` block (added either at genesis or by hand
later) wires this credential into the gateway:

```toml
[[providers.entries]]
id          = "anthropic-prod"
kind        = "Anthropic"
credentials = "anthropic-prod.toml"
default_model = "claude-haiku-4-5"
```

After editing `policy.toml`, re-sign it:

```bash
raxis policy sign \
  "$RAXIS_DATA_DIR/policy/policy.toml" \
  --key "$HOME/raxis-keys/operator_private.pem"
```

> **Never commit a real `credentials/*.toml` to git.** Every scenario's
> `credential.toml` ships with placeholder values; you fill them in
> locally and they stay local.

---

## Step 6 — Allowlist your worktree roots

Every scenario uses a temporary directory for its scratch worktrees.
Allowlist that prefix in `policy.toml`:

```toml
[sessions]
allowed_worktree_roots = ["/tmp", "/var/folders"]   # add your scratch parents
```

Re-sign:

```bash
raxis policy sign \
  "$RAXIS_DATA_DIR/policy/policy.toml" \
  --key "$HOME/raxis-keys/operator_private.pem"
```

---

## Step 7 — Start the kernel

```bash
export RAXIS_DATA_DIR="$HOME/.raxis-demo"
raxis-kernel
```

You should see JSON-formatted log lines like:

```json
{"level":"info","event":"PolicyLoaded","epoch_id":1}
{"level":"info","event":"KeyRegistryLoaded"}
{"level":"info","event":"AuditChainGenesis"}
{"level":"info","event":"KernelStarted"}
```

The kernel auto-spawns and supervises the gateway subprocess. Leave
this terminal running for the lifetime of the scenarios; switch to a
second terminal for the scenario commands.

> **Running RAXIS as a system daemon.** For long-lived production
> hosts, the easiest path is the one-liner:
>
> ```bash
> # User-level install — runs as your user, ~/.config/systemd/user/
> # on Linux or ~/Library/LaunchAgents/ on macOS.
> raxis kernel install
>
> # System-level install — runs as the dedicated `_raxis` user.
> sudo raxis kernel install --system
> ```
>
> The CLI templates the unit file with this binary's resolved path
> and your current `--data-dir`, then prints the `systemctl --user
> enable --now raxis-kernel` (Linux) or `launchctl bootstrap`
> (macOS) command to start the service. To uninstall, run
> `raxis kernel uninstall` (add `--system` if you installed system-wide).
>
> The hand-edited reference templates remain available under
> `raxis/installer/` for operators who want to inspect or customize
> them before installing:
>
> - macOS — [`raxis/installer/launchd/com.raxis.kernel.plist`](../installer/launchd/com.raxis.kernel.plist)
>   plus [`raxis/installer/newsyslog/raxis.conf`](../installer/newsyslog/raxis.conf) for log rotation.
> - Linux — [`raxis/installer/systemd/raxis-kernel.service`](../installer/systemd/raxis-kernel.service);
>   journald handles log rotation.
>
> Each file is self-documenting at the top with install / uninstall
> commands and the spec section it implements.

---

## Step 8 — Confirm the install is healthy

```bash
export RAXIS_OPERATOR_KEY="$HOME/raxis-keys/operator_private.pem"

raxis status                                              # one-line health rollup
raxis doctor                                              # full preflight
raxis verify-chain                                        # audit chain end-to-end check
```

`doctor` should print all-green. `verify-chain` should report a
non-zero record count and zero gaps.

---

## Confirming an existing install

If you are returning to a machine that has already run genesis, the
following three commands answer "is this install ready?":

```bash
test -f "$RAXIS_DATA_DIR/policy/policy.toml"   && echo "policy: present"
test -f "$RAXIS_DATA_DIR/audit/segment-000.jsonl" && echo "audit chain: present"
raxis verify-chain | tail -3                                # all-green
```

If all three succeed, **do not re-run `raxis genesis`** — it would
refuse anyway, but skipping it saves operator confusion.

To start the kernel against an existing install, all you need is:

```bash
export RAXIS_DATA_DIR="$HOME/.raxis-demo"     # whatever you used originally
export RAXIS_OPERATOR_KEY="$HOME/raxis-keys/operator_private.pem"
raxis-kernel
```

---

## Tear-down

If you want to wipe the whole install and start over:

```bash
# In the kernel terminal: Ctrl-C (clean shutdown)
rm -rf "$RAXIS_DATA_DIR"
rm -rf "$HOME/raxis-keys"          # optional — only if you want a fresh keypair too
```

For per-scenario tear-down, see each scenario's "Tear-down" section.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `Algorithm ed25519 not found` on `openssl genpkey` | macOS LibreSSL | Install Homebrew `openssl@3` and prepend its `bin/` to `$PATH`. |
| `genesis: refusing to overwrite existing data dir` | Genesis already ran here | Confirm the install is healthy ("Confirming…" section). To force-redo: `rm -rf "$RAXIS_DATA_DIR"` first. |
| `--operator-key <path> is required for this command` | Operator-socket commands need the key for the kernel's challenge-response | `export RAXIS_OPERATOR_KEY="$HOME/raxis-keys/operator_private.pem"`. |
| `FAIL_WORKTREE_OUTSIDE_ALLOWED_ROOTS` on `session create` | Scenario's worktree path not under any allowlisted root | Edit `policy.toml`'s `[sessions].allowed_worktree_roots`, re-sign. |
| `BOOT_ERR_CREDENTIAL_MODE` | A `providers/<x>.toml` is not mode `0600` | `chmod 600 "$RAXIS_DATA_DIR/providers/"*.toml`. |
| `BOOT_ERR_ISOLATION_UNAVAILABLE` | No KVM (Linux) or AVF (macOS) reachable | Verify `/dev/kvm` is present on Linux (member of `kvm` group) or you're on macOS 13+; rerun `raxis doctor`. |
| `cannot connect to operator socket` | Kernel not running, or `$RAXIS_DATA_DIR` mismatched between terminals | Confirm `raxis-kernel` is up; `echo $RAXIS_DATA_DIR` must match. |

---

## Cross-references

- [`raxis/README.md`](../README.md) — Quick Start, V1 vs V2 capability matrix.
- [`specs/v1/cli-ceremony.md`](../specs/v1/cli-ceremony.md) — full CLI surface.
- [`specs/v2/system-requirements.md`](../specs/v2/system-requirements.md) — hardware + software requirements.
- [`specs/v2/credential-proxy.md`](../specs/v2/credential-proxy.md) — credential proxy architecture.
- [`specs/v2/v2-deep-spec.md`](../specs/v2/v2-deep-spec.md) — V2 architecture deep-dive.
